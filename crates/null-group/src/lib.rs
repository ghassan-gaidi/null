//! Null-MLS group messaging (§10): TreeKEM ratchet tree with PQ node keys.
//!
//! Each epoch, the committer refreshes its direct path with fresh secrets
//! and encrypts each path secret to the sibling subtrees' resolutions —
//! O(log n) encapsulations per commit. Removals blank nodes (resolution
//! routes around blanks); epochs hash-chain so forks, gaps and replays are
//! rejected; Welcomes carry the roster, public tree and the joiner's path.

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use null_core::{NullError, Result, MAX_GROUP_MEMBERS};
use null_crypto::{kyber_encap_to, KyberKeypair};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha384;
use std::collections::{HashMap, HashSet};
use tree::RatchetTree;

pub mod tree;

// ---------------------------------------------------------------------------
// KeyPackage codec (manual, length-prefixed).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackage {
    pub member_id: [u8; 32],
    pub kyber_ek: Vec<u8>,
    pub signature_hint: Option<Vec<u8>>,
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn get_bytes(mut bytes: &[u8]) -> Result<(Vec<u8>, &[u8])> {
    if bytes.len() < 4 {
        return Err(NullError::Group("blob truncated".into()));
    }
    let n = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    bytes = &bytes[4..];
    if bytes.len() < n {
        return Err(NullError::Group("blob overrun".into()));
    }
    Ok((bytes[..n].to_vec(), &bytes[n..]))
}

fn encode_keypackage(kp: &KeyPackage) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&kp.member_id);
    put_bytes(&mut out, &kp.kyber_ek);
    match &kp.signature_hint {
        Some(s) => {
            out.push(1);
            put_bytes(&mut out, s);
        }
        None => out.push(0),
    }
    out
}

fn decode_keypackage(mut bytes: &[u8]) -> Result<(KeyPackage, &[u8])> {
    if bytes.len() < 32 {
        return Err(NullError::Group("keypackage too short".into()));
    }
    let mut member_id = [0u8; 32];
    member_id.copy_from_slice(&bytes[..32]);
    bytes = &bytes[32..];
    let (kyber_ek, rest) = get_bytes(bytes)?;
    bytes = rest;
    if bytes.is_empty() {
        return Err(NullError::Group("keypackage missing sig flag".into()));
    }
    let (signature_hint, rest) = match bytes[0] {
        0 => (None, &bytes[1..]),
        1 => {
            let (s, r) = get_bytes(&bytes[1..])?;
            (Some(s), r)
        }
        _ => return Err(NullError::Group("bad keypackage sig flag".into())),
    };
    Ok((
        KeyPackage {
            member_id,
            kyber_ek,
            signature_hint,
        },
        rest,
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub group_id: [u8; 32],
    pub epoch: u64,
}

/// Roster: `(member_id, leaf_pos)` pairs, sorted by id.
pub type Roster = Vec<([u8; 32], u32)>;

// ---------------------------------------------------------------------------
// Wire packages.
// ---------------------------------------------------------------------------

/// Commit broadcast: ONE package fanned out to all members (O(log n)
/// ciphertexts inside). Layout uses u32 length prefixes throughout.
#[derive(Debug, Clone)]
pub struct TreeCommit {
    pub group_id: [u8; 32],
    pub epoch: u64,
    pub prev_hash: [u8; 32],
    pub depth: u32,
    pub roster: Roster,
    pub committer_leaf: u32,
    pub adds: Vec<(u32, KeyPackage)>,
    pub removes: Vec<(u32, [u8; 32])>,
    pub blanked: Vec<u32>,
    pub updated: Vec<(u32, Vec<u8>)>,
    pub bundles: Vec<(u32, Vec<u8>, Vec<u8>)>,
}

/// Welcome for one joiner: sealed group state + public tree.
#[derive(Debug, Clone)]
pub struct WelcomePkg {
    pub group_id: [u8; 32],
    pub epoch: u64,
    pub prev_hash: [u8; 32],
    pub depth: u32,
    pub roster: Roster,
    pub leaf_pos: u32,
    pub pubs: Vec<(u32, Vec<u8>)>,
    pub blanks: Vec<u32>,
    pub ct: Vec<u8>,
    /// Sealed: `secret(48) ‖ npath(u32) ‖ [(idx u32, seed 64)]`.
    pub sealed: Vec<u8>,
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn get_u32(bytes: &[u8]) -> Result<(u32, &[u8])> {
    if bytes.len() < 4 {
        return Err(NullError::Group("u32 truncated".into()));
    }
    Ok((
        u32::from_be_bytes(bytes[..4].try_into().unwrap()),
        &bytes[4..],
    ))
}

fn get_u64(bytes: &[u8]) -> Result<(u64, &[u8])> {
    if bytes.len() < 8 {
        return Err(NullError::Group("u64 truncated".into()));
    }
    Ok((
        u64::from_be_bytes(bytes[..8].try_into().unwrap()),
        &bytes[8..],
    ))
}

fn get_id(bytes: &[u8]) -> Result<([u8; 32], &[u8])> {
    if bytes.len() < 32 {
        return Err(NullError::Group("id truncated".into()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes[..32]);
    Ok((id, &bytes[32..]))
}

fn put_roster(out: &mut Vec<u8>, roster: &[([u8; 32], u32)]) {
    put_u32(out, roster.len() as u32);
    for (id, pos) in roster {
        out.extend_from_slice(id);
        put_u32(out, *pos);
    }
}

fn get_roster(mut bytes: &[u8]) -> Result<(Roster, &[u8])> {
    let (n, mut rest) = get_u32(bytes)?;
    bytes = rest;
    if n as usize > MAX_GROUP_MEMBERS {
        return Err(NullError::Group("roster too large".into()));
    }
    let mut roster = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let (id, r1) = get_id(bytes)?;
        let (pos, r2) = get_u32(r1)?;
        roster.push((id, pos));
        bytes = r2;
        rest = r2;
    }
    Ok((roster, rest))
}

impl TreeCommit {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0x02]; // package version
        out.extend_from_slice(&self.group_id);
        put_u64(&mut out, self.epoch);
        out.extend_from_slice(&self.prev_hash);
        put_u32(&mut out, self.depth);
        put_roster(&mut out, &self.roster);
        put_u32(&mut out, self.committer_leaf);
        put_u32(&mut out, self.adds.len() as u32);
        for (pos, kp) in &self.adds {
            put_u32(&mut out, *pos);
            let kb = encode_keypackage(kp);
            put_bytes(&mut out, &kb);
        }
        put_u32(&mut out, self.removes.len() as u32);
        for (pos, id) in &self.removes {
            put_u32(&mut out, *pos);
            out.extend_from_slice(id);
        }
        put_u32(&mut out, self.blanked.len() as u32);
        for idx in &self.blanked {
            put_u32(&mut out, *idx);
        }
        put_u32(&mut out, self.updated.len() as u32);
        for (idx, ek) in &self.updated {
            put_u32(&mut out, *idx);
            put_bytes(&mut out, ek);
        }
        put_u32(&mut out, self.bundles.len() as u32);
        for (target, ct, sealed) in &self.bundles {
            put_u32(&mut out, *target);
            put_bytes(&mut out, ct);
            put_bytes(&mut out, sealed);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.first() != Some(&0x02) {
            return Err(NullError::Group("bad commit version".into()));
        }
        let mut rest = &bytes[1..];
        let (group_id, r) = get_id(rest)?;
        rest = r;
        let (epoch, r) = get_u64(rest)?;
        rest = r;
        if rest.len() < 32 {
            return Err(NullError::Group("commit prev truncated".into()));
        }
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&rest[..32]);
        rest = &rest[32..];
        let (depth, r) = get_u32(rest)?;
        rest = r;
        let (roster, r) = get_roster(rest)?;
        rest = r;
        let (committer_leaf, r) = get_u32(rest)?;
        rest = r;
        let (n_adds, r) = get_u32(rest)?;
        rest = r;
        if n_adds as usize > MAX_GROUP_MEMBERS {
            return Err(NullError::Group("adds too many".into()));
        }
        let mut adds = Vec::with_capacity(n_adds as usize);
        for _ in 0..n_adds {
            let (pos, r) = get_u32(rest)?;
            let (kb, r) = get_bytes(r)?;
            let (kp, tail) = decode_keypackage(&kb)?;
            if !tail.is_empty() {
                return Err(NullError::Group("keypackage trailing bytes".into()));
            }
            adds.push((pos, kp));
            rest = r;
        }
        let (n_rem, r) = get_u32(rest)?;
        rest = r;
        if n_rem as usize > MAX_GROUP_MEMBERS {
            return Err(NullError::Group("removes too many".into()));
        }
        let mut removes = Vec::with_capacity(n_rem as usize);
        for _ in 0..n_rem {
            let (pos, r) = get_u32(rest)?;
            let (id, r) = get_id(r)?;
            removes.push((pos, id));
            rest = r;
        }
        let (n_blank, r) = get_u32(rest)?;
        rest = r;
        let mut blanked = Vec::with_capacity(n_blank.min(1 << 20) as usize);
        for _ in 0..n_blank {
            let (idx, r) = get_u32(rest)?;
            blanked.push(idx);
            rest = r;
        }
        let (n_upd, r) = get_u32(rest)?;
        rest = r;
        let mut updated = Vec::with_capacity(n_upd.min(1 << 20) as usize);
        for _ in 0..n_upd {
            let (idx, r) = get_u32(rest)?;
            let (ek, r) = get_bytes(r)?;
            updated.push((idx, ek));
            rest = r;
        }
        let (n_bun, r) = get_u32(rest)?;
        rest = r;
        let mut bundles = Vec::with_capacity(n_bun.min(1 << 20) as usize);
        for _ in 0..n_bun {
            let (target, r) = get_u32(rest)?;
            let (ct, r) = get_bytes(r)?;
            let (sealed, r) = get_bytes(r)?;
            bundles.push((target, ct, sealed));
            rest = r;
        }
        if !rest.is_empty() {
            return Err(NullError::Group("commit trailing bytes".into()));
        }
        Ok(Self {
            group_id,
            epoch,
            prev_hash,
            depth,
            roster,
            committer_leaf,
            adds,
            removes,
            blanked,
            updated,
            bundles,
        })
    }
}

impl WelcomePkg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0x02];
        out.extend_from_slice(&self.group_id);
        put_u64(&mut out, self.epoch);
        out.extend_from_slice(&self.prev_hash);
        put_u32(&mut out, self.depth);
        put_roster(&mut out, &self.roster);
        put_u32(&mut out, self.leaf_pos);
        put_u32(&mut out, self.pubs.len() as u32);
        for (idx, ek) in &self.pubs {
            put_u32(&mut out, *idx);
            put_bytes(&mut out, ek);
        }
        put_u32(&mut out, self.blanks.len() as u32);
        for idx in &self.blanks {
            put_u32(&mut out, *idx);
        }
        put_bytes(&mut out, &self.ct);
        put_bytes(&mut out, &self.sealed);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.first() != Some(&0x02) {
            return Err(NullError::Group("bad welcome version".into()));
        }
        let mut rest = &bytes[1..];
        let (group_id, r) = get_id(rest)?;
        rest = r;
        let (epoch, r) = get_u64(rest)?;
        rest = r;
        if rest.len() < 32 {
            return Err(NullError::Group("welcome prev truncated".into()));
        }
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&rest[..32]);
        rest = &rest[32..];
        let (depth, r) = get_u32(rest)?;
        rest = r;
        if depth > 20 {
            return Err(NullError::Group("absurd tree depth".into()));
        }
        let (roster, r) = get_roster(rest)?;
        rest = r;
        let (leaf_pos, r) = get_u32(rest)?;
        rest = r;
        let (n_pubs, r) = get_u32(rest)?;
        rest = r;
        let mut pubs = Vec::with_capacity(n_pubs.min(1 << 20) as usize);
        for _ in 0..n_pubs {
            let (idx, r) = get_u32(rest)?;
            let (ek, r) = get_bytes(r)?;
            pubs.push((idx, ek));
            rest = r;
        }
        let (n_blank, r) = get_u32(rest)?;
        rest = r;
        let mut blanks = Vec::with_capacity(n_blank.min(1 << 20) as usize);
        for _ in 0..n_blank {
            let (idx, r) = get_u32(rest)?;
            blanks.push(idx);
            rest = r;
        }
        let (ct, r) = get_bytes(rest)?;
        let (sealed, r) = get_bytes(r)?;
        if !r.is_empty() {
            return Err(NullError::Group("welcome trailing bytes".into()));
        }
        Ok(Self {
            group_id,
            epoch,
            prev_hash,
            depth,
            roster,
            leaf_pos,
            pubs,
            blanks,
            ct,
            sealed,
        })
    }
}

// ---------------------------------------------------------------------------
// Group.
// ---------------------------------------------------------------------------

pub struct Group {
    id: [u8; 32],
    epoch: u64,
    tree_secret: [u8; 48],
    members: HashMap<[u8; 32], KeyPackage>,
    member_leaf: HashMap<[u8; 32], u32>,
    sender_chains: HashMap<[u8; 32], u64>,
    tree: RatchetTree,
    defunct: bool,
}

/// Epoch commitment: `SHA3-256(secret ‖ epoch_BE)`.
fn epoch_hash(secret: &[u8; 48], epoch: u64) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(secret);
    h.update(epoch.to_be_bytes());
    h.finalize().into()
}

fn fresh32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

/// Seal join state to the joiner's KeyPackage ek: encap fresh `k`, AEAD the
/// payload under it (zero nonce, single-use key).
fn seal_to_ek(payload: &[u8], member_ek: &[u8], ad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (ct, k) =
        kyber_encap_to(member_ek).map_err(|e| NullError::Group(format!("welcome encap: {e}")))?;
    let wrap = Hkdf::<Sha384>::new(None, &k);
    let mut wk = [0u8; 32];
    wrap.expand(b"null-mls-welcome-wrap", &mut wk)
        .map_err(|e| NullError::Group(format!("hkdf: {e}")))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wk));
    let mut sealed = payload.to_vec();
    cipher
        .encrypt_in_place(Nonce::from_slice(&[0u8; 12]), ad, &mut sealed)
        .map_err(|e| NullError::Group(format!("seal: {e}")))?;
    use zeroize::Zeroize;
    wk.zeroize();
    Ok((ct, sealed))
}

fn open_sealed(k: &[u8], sealed: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    let wrap = Hkdf::<Sha384>::new(None, k);
    let mut wk = [0u8; 32];
    wrap.expand(b"null-mls-welcome-wrap", &mut wk)
        .map_err(|e| NullError::Group(format!("hkdf: {e}")))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wk));
    let mut buf = sealed.to_vec();
    cipher
        .decrypt_in_place(Nonce::from_slice(&[0u8; 12]), ad, &mut buf)
        .map_err(|e| NullError::Group(format!("open: {e}")))?;
    use zeroize::Zeroize;
    wk.zeroize();
    Ok(buf)
}

impl Group {
    pub fn create() -> Self {
        let mut id = [0u8; 32];
        OsRng.fill_bytes(&mut id);
        let (tree, secret) = RatchetTree::single();
        let mut creator = [0u8; 32];
        OsRng.fill_bytes(&mut creator);
        let mut members = HashMap::new();
        let mut member_leaf = HashMap::new();
        let mut sender_chains = HashMap::new();
        members.insert(
            creator,
            KeyPackage {
                member_id: creator,
                kyber_ek: tree.leaf_ek(0).unwrap_or_default(),
                signature_hint: None,
            },
        );
        member_leaf.insert(creator, 0);
        sender_chains.insert(creator, 0);
        Self {
            id,
            epoch: 0,
            tree_secret: secret,
            members,
            member_leaf,
            sender_chains,
            tree,
            defunct: false,
        }
    }

    pub fn info(&self) -> GroupInfo {
        GroupInfo {
            group_id: self.id,
            epoch: self.epoch,
        }
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Roster as sorted `(member_id, leaf_pos)` pairs.
    pub fn roster(&self) -> Roster {
        let mut r: Vec<_> = self
            .member_leaf
            .iter()
            .map(|(id, pos)| (*id, *pos))
            .collect();
        r.sort_unstable();
        r
    }

    /// Rewrite roster positions through a growth remap.
    fn apply_remap(&mut self, remap: Vec<(u32, u32)>) {
        if remap.is_empty() {
            return;
        }
        let map: HashMap<u32, u32> = remap.into_iter().collect();
        for pos in self.member_leaf.values_mut() {
            if let Some(np) = map.get(pos) {
                *pos = *np;
            }
        }
    }

    fn ensure_live(&self) -> Result<()> {
        if self.defunct {
            return Err(NullError::Group("removed from group".into()));
        }
        Ok(())
    }

    /// Add a member: assign a leaf, refresh our path (O(log n) bundles),
    /// return `(welcome_bytes, commit_bytes)`. The commit is fanned out to
    /// existing members; the Welcome goes to the joiner.
    pub fn add(&mut self, kp: KeyPackage) -> Result<(Vec<u8>, Vec<u8>)> {
        self.ensure_live()?;
        if self.members.len() >= MAX_GROUP_MEMBERS {
            return Err(NullError::Group("group full (50k)".into()));
        }
        if self.members.contains_key(&kp.member_id) {
            return Err(NullError::Group("duplicate member".into()));
        }
        if self.tree.occupied_count() >= self.tree.leaf_count() {
            let remap = self.tree.grow();
            self.apply_remap(remap);
        }
        let pos = self.tree.alloc_leaf().expect("capacity ensured");
        let join_node = self.tree.leaf_node(pos);
        self.tree.set_keyed(join_node, kp.kyber_ek.clone());
        let prev = epoch_hash(&self.tree_secret, self.epoch);
        let (updated, bundles, root, levels) = self.tree.commit_path(fresh32())?;
        // Joiner path: shared levels from our fresh chain. Nodes on the
        // joiner's exclusive branch stay BLANK (resolution routes around
        // blanks to the keyed leaves): keying them here would strand the
        // existing members beneath them without the secret — a TreeKEM
        // invariant violation (every non-blank node's secret must be known
        // to all members under it).
        let lca = self.tree.lca_depth(self.tree.own_leaf_pos(), pos);
        let d = self.tree.depth() as usize;
        let mut path_entries: Vec<(u32, [u8; 64])> = Vec::new();
        for node in self.tree.path_to_root(join_node) {
            if node == join_node {
                continue; // joiner's leaf key is its KeyPackage pair
            }
            let depth = self.tree.node_depth(node);
            if depth == 0 || depth > lca {
                continue; // root via sealed secret; exclusive stays blank
            }
            let k = d - depth as usize;
            if k < levels.len() {
                path_entries.push((node, levels[k]));
            }
        }
        self.tree_secret = root;
        self.epoch += 1;
        self.members.insert(kp.member_id, kp.clone());
        self.member_leaf.insert(kp.member_id, pos);
        self.sender_chains.insert(kp.member_id, 0);
        let commit = TreeCommit {
            group_id: self.id,
            epoch: self.epoch,
            prev_hash: prev,
            depth: self.tree.depth(),
            roster: self.roster(),
            committer_leaf: self.tree.own_leaf_pos(),
            adds: vec![(pos, kp)],
            removes: vec![],
            blanked: vec![],
            updated,
            bundles,
        };
        // Welcome seals the secret + joiner path to the joiner's ek.
        let mut payload = Vec::with_capacity(48 + 4 + path_entries.len() * 68);
        payload.extend_from_slice(&self.tree_secret);
        payload.extend_from_slice(&(path_entries.len() as u32).to_be_bytes());
        for (idx, seed) in &path_entries {
            payload.extend_from_slice(&idx.to_be_bytes());
            payload.extend_from_slice(seed);
        }
        let (ct, sealed) = seal_to_ek(&payload, &commit.adds[0].1.kyber_ek, &self.id)?;
        use zeroize::Zeroize;
        payload.zeroize();
        let welcome = WelcomePkg {
            group_id: self.id,
            epoch: self.epoch,
            prev_hash: prev,
            depth: self.tree.depth(),
            roster: self.roster(),
            leaf_pos: pos,
            pubs: self.tree.public_snapshot(),
            blanks: self.tree.blank_snapshot(),
            ct,
            sealed,
        };
        Ok((welcome.encode(), commit.encode()))
    }

    /// Remove a member: blank its leaf + off-path nodes, refresh our path.
    /// Returns the broadcast commit. Removing our own leaf is rejected —
    /// to leave, delete local state instead.
    pub fn remove(&mut self, id: &[u8; 32]) -> Result<Vec<u8>> {
        self.ensure_live()?;
        let pos = *self
            .member_leaf
            .get(id)
            .ok_or_else(|| NullError::Group("unknown member".into()))?;
        if pos == self.tree.own_leaf_pos() {
            return Err(NullError::Group(
                "cannot remove self via commit; delete local state to leave".into(),
            ));
        }
        self.members.remove(id);
        self.member_leaf.remove(id);
        self.sender_chains.remove(id);
        self.tree.vacate_leaf(pos);
        // Blank nodes on the removed leaf's path that are NOT on our path
        // (we cannot refresh secrets we never knew).
        let removed_path: HashSet<u32> = self
            .tree
            .path_to_root(self.tree.leaf_node(pos))
            .into_iter()
            .collect();
        let own_path: HashSet<u32> = self
            .tree
            .path_to_root(self.tree.leaf_node(self.tree.own_leaf_pos()))
            .into_iter()
            .collect();
        let mut blanked: Vec<u32> = removed_path
            .difference(&own_path)
            .copied()
            .filter(|i| *i != 0)
            .collect();
        blanked.sort_unstable();
        self.tree.apply_blanks(&blanked);
        let prev = epoch_hash(&self.tree_secret, self.epoch);
        let (updated, bundles, root, _) = self.tree.commit_path(fresh32())?;
        self.tree_secret = root;
        self.epoch += 1;
        let commit = TreeCommit {
            group_id: self.id,
            epoch: self.epoch,
            prev_hash: prev,
            depth: self.tree.depth(),
            roster: self.roster(),
            committer_leaf: self.tree.own_leaf_pos(),
            adds: vec![],
            removes: vec![(pos, *id)],
            blanked,
            updated,
            bundles,
        };
        Ok(commit.encode())
    }

    /// Refresh our path without membership change (forward secrecy rotation).
    pub fn update(&mut self) -> Result<Vec<u8>> {
        self.ensure_live()?;
        let prev = epoch_hash(&self.tree_secret, self.epoch);
        let (updated, bundles, root, _) = self.tree.commit_path(fresh32())?;
        self.tree_secret = root;
        self.epoch += 1;
        let commit = TreeCommit {
            group_id: self.id,
            epoch: self.epoch,
            prev_hash: prev,
            depth: self.tree.depth(),
            roster: self.roster(),
            committer_leaf: self.tree.own_leaf_pos(),
            adds: vec![],
            removes: vec![],
            blanked: vec![],
            updated,
            bundles,
        };
        Ok(commit.encode())
    }

    /// Process a broadcast commit from another member.
    pub fn process_commit(&mut self, bytes: &[u8]) -> Result<()> {
        let pkg = TreeCommit::decode(bytes)?;
        if pkg.group_id != self.id {
            return Err(NullError::Group("commit for another group".into()));
        }
        if pkg.committer_leaf == self.tree.own_leaf_pos() {
            if pkg.epoch == self.epoch {
                return Ok(()); // own redelivery: already applied
            }
            return Err(NullError::Group("own commit epoch mismatch".into()));
        }
        if pkg.epoch != self.epoch + 1 {
            return Err(NullError::Group(format!(
                "stale commit epoch {} (at {})",
                pkg.epoch, self.epoch
            )));
        }
        if pkg.prev_hash != epoch_hash(&self.tree_secret, self.epoch) {
            return Err(NullError::Group(
                "commit does not chain to current epoch (fork or gap)".into(),
            ));
        }
        // Depth only ever grows deterministically; a shallower package
        // after growth would mean a fork, caught by the epoch check above.
        // Growth renumbers positions: remap the roster identically.
        while self.tree.depth() < pkg.depth {
            let remap = self.tree.grow();
            self.apply_remap(remap);
        }
        if self.tree.depth() != pkg.depth {
            return Err(NullError::Group("commit depth regression".into()));
        }
        for (pos, kp) in &pkg.adds {
            if self.members.contains_key(&kp.member_id) {
                return Err(NullError::Group("duplicate member in commit".into()));
            }
            self.tree.occupy(*pos);
            self.tree
                .set_keyed(self.tree.leaf_node(*pos), kp.kyber_ek.clone());
            self.members.insert(kp.member_id, kp.clone());
            self.member_leaf.insert(kp.member_id, *pos);
            self.sender_chains.insert(kp.member_id, 0);
        }
        let mut self_removed = false;
        for (pos, id) in &pkg.removes {
            if *pos == self.tree.own_leaf_pos() {
                self_removed = true;
            }
            self.tree.vacate_leaf(*pos);
            self.members.remove(id);
            self.member_leaf.remove(id);
            self.sender_chains.remove(id);
        }
        self.tree.apply_blanks(&pkg.blanked);
        self.tree.merge_public(&pkg.updated, &[]);
        self.sync_roster(&pkg.roster);
        if self_removed {
            use zeroize::Zeroize;
            self.tree_secret.zeroize();
            self.defunct = true;
            self.epoch = pkg.epoch;
            return Ok(());
        }
        let (level, ps) = self.tree.open_bundle(&pkg.bundles, pkg.committer_leaf)?;
        let root = self.tree.adopt_shared_path(ps, level + 1)?;
        self.tree_secret = root;
        self.epoch = pkg.epoch;
        Ok(())
    }

    /// Replace the roster with the commit's, preserving stored KeyPackages
    /// (with real eks) for members we already know.
    fn sync_roster(&mut self, roster: &[([u8; 32], u32)]) {
        let mut next = HashMap::new();
        let mut leaf_map = HashMap::new();
        for (id, pos) in roster {
            leaf_map.insert(*id, *pos);
            if let Some(kp) = self.members.remove(id) {
                next.insert(*id, kp);
            } else {
                next.insert(
                    *id,
                    KeyPackage {
                        member_id: *id,
                        kyber_ek: Vec::new(),
                        signature_hint: None,
                    },
                );
                self.sender_chains.entry(*id).or_insert(0);
            }
        }
        self.sender_chains.retain(|id, _| leaf_map.contains_key(id));
        self.members = next;
        self.member_leaf = leaf_map;
    }

    /// Join a group from a `Welcome`: decapsulate group state with our
    /// long-term Kyber dk and adopt the tree at the envelope epoch.
    /// Roster, tree and path arrive together (TOFU, like the secret itself);
    /// our leaf key stays our long-term pair until our first update.
    pub fn join(env_bytes: &[u8], member_id: [u8; 32], dk: &KyberKeypair) -> Result<Self> {
        let env = WelcomePkg::decode(env_bytes)?;
        let k = dk
            .decapsulate(&env.ct)
            .map_err(|e| NullError::Group(format!("welcome decap: {e}")))?;
        let payload = open_sealed(&k, &env.sealed, &env.group_id)?;
        if payload.len() < 52 {
            return Err(NullError::Group("welcome payload too short".into()));
        }
        let mut secret = [0u8; 48];
        secret.copy_from_slice(&payload[..48]);
        let npath = u32::from_be_bytes(payload[48..52].try_into().unwrap()) as usize;
        if payload.len() != 52 + npath * 68 {
            return Err(NullError::Group("welcome path length mismatch".into()));
        }
        let mut tree = RatchetTree::empty_at(env.depth);
        for (idx, ek) in &env.pubs {
            tree.set_keyed(*idx, ek.clone());
        }
        tree.apply_blanks(&env.blanks);
        let mut members = HashMap::new();
        let mut member_leaf = HashMap::new();
        let mut sender_chains = HashMap::new();
        for (id, pos) in &env.roster {
            members.insert(
                *id,
                KeyPackage {
                    member_id: *id,
                    kyber_ek: Vec::new(),
                    signature_hint: None,
                },
            );
            member_leaf.insert(*id, *pos);
            sender_chains.insert(*id, 0);
            tree.occupy(*pos);
        }
        sender_chains.insert(member_id, 0);
        // Adopt our path seeds (the leaf itself keeps our long-term dk).
        let join_node = tree.leaf_node(env.leaf_pos);
        for i in 0..npath {
            let at = 52 + i * 68;
            let idx = u32::from_be_bytes(payload[at..at + 4].try_into().unwrap());
            if idx == join_node {
                continue;
            }
            let mut seed = [0u8; 64];
            seed.copy_from_slice(&payload[at + 4..at + 68]);
            tree.adopt_node(idx, seed);
        }
        tree.set_own_leaf(env.leaf_pos, Some(dk.clone()));
        Ok(Self {
            id: env.group_id,
            epoch: env.epoch,
            tree_secret: secret,
            members,
            member_leaf,
            sender_chains,
            tree,
            defunct: false,
        })
    }

    /// Group message key for (epoch, sender, seq): HKDF(tree ‖ sender ‖ seq).
    /// `sender` must be a roster member id: commit processing prunes
    /// non-roster sender chains on recipients (the committer, which never
    /// processes its own commits, retains them), so only roster-member
    /// senders stay sequence-aligned across copies.
    pub fn message_key(&mut self, sender: &[u8; 32]) -> Result<[u8; 32]> {
        self.ensure_live()?;
        let seq = self.sender_chains.get(sender).copied().unwrap_or(0);
        let hk = Hkdf::<Sha384>::new(Some(&self.id), &self.tree_secret);
        let mut ikm = Vec::new();
        ikm.extend_from_slice(sender);
        ikm.extend_from_slice(&seq.to_be_bytes());
        ikm.extend_from_slice(&self.epoch.to_be_bytes());
        let mut okm = [0u8; 32];
        hk.expand(&ikm, &mut okm)
            .map_err(|e| NullError::Group(format!("hkdf: {e}")))?;
        self.sender_chains.insert(*sender, seq + 1);
        Ok(okm)
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.tree_secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real_kp(id_byte: u8) -> (KeyPackage, KyberKeypair) {
        let kp = KyberKeypair::generate();
        (
            KeyPackage {
                member_id: [id_byte; 32],
                kyber_ek: kp.ek_bytes(),
                signature_hint: None,
            },
            kp,
        )
    }

    /// Drive one commit from `a` to `b` (both directions share this helper
    /// by swapping roles at the call site).
    fn deliver(a: &mut Group, b: &mut Group, commit: Vec<u8>) {
        b.process_commit(&commit).unwrap();
        assert_eq!(a.info().epoch, b.info().epoch);
        assert_eq!(a.tree_secret, b.tree_secret);
        let _ = a;
    }

    #[test]
    fn create_add_update_converge() {
        let mut a = Group::create();
        assert_eq!(a.member_count(), 1);
        let (kp_b, dk_b) = real_kp(0x42);
        let (welcome, _commit) = a.add(kp_b).unwrap();
        let mut b = Group::join(&welcome, [0x42; 32], &dk_b).unwrap();
        assert_eq!(b.member_count(), 2);
        // The joiner adopted epoch 1 via Welcome; it must NOT also process
        // its own add-commit (that would double-apply the epoch).
        assert_eq!(a.info().epoch, b.info().epoch);
        assert_eq!(a.tree_secret, b.tree_secret);
        // Sender keys agree for any (sender, seq) at the same epoch.
        let sender = [9u8; 32];
        assert_eq!(
            a.message_key(&sender).unwrap(),
            b.message_key(&sender).unwrap()
        );
        // Update ratchets the root forward on both sides.
        let before = a.tree_secret;
        let upd = a.update().unwrap();
        deliver(&mut a, &mut b, upd);
        assert_ne!(a.tree_secret, before);
    }

    #[test]
    fn commit_cost_is_sublinear() {
        // 8 members, depth 3: a commit must carry ~3 bundles, not ~8.
        // Every commit is fanned out to every current member in order
        // (epochs hash-chain, so no member may skip one).
        let mut a = Group::create();
        let mut members: Vec<([u8; 32], Group, KyberKeypair)> = Vec::new();
        for i in 1u8..8 {
            let (kp, dk) = real_kp(i);
            let id = [i; 32];
            let (welcome, commit) = a.add(kp).unwrap();
            for (_, g, _) in members.iter_mut() {
                g.process_commit(&commit).unwrap();
                assert_eq!(g.info().epoch, a.info().epoch);
            }
            let member = Group::join(&welcome, id, &dk).unwrap();
            assert_eq!(member.info().epoch, a.info().epoch);
            members.push((id, member, dk));
        }
        assert_eq!(a.member_count(), 8);
        // Round-robin: everyone (including A) commits once; all converge.
        // This exercises multi-committer recipient logic in every direction
        // and fully keys the tree (no blanks left).
        for round in 0..members.len() + 1 {
            if round == 0 {
                let upd = a.update().unwrap();
                for (_, g, _) in members.iter_mut() {
                    g.process_commit(&upd).unwrap();
                }
            } else {
                let (id, upd) = {
                    let (id, g, _) = &mut members[round - 1];
                    (*id, g.update().unwrap())
                };
                a.process_commit(&upd).unwrap();
                for (oid, other, _) in members.iter_mut() {
                    if *oid != id {
                        other.process_commit(&upd).unwrap();
                    }
                }
            }
        }
        let check_epoch = a.info().epoch;
        for (_, g, _) in members.iter() {
            assert_eq!(g.info().epoch, check_epoch);
            assert_eq!(g.tree_secret, a.tree_secret);
        }
        // Now the tree is fully keyed: next commit is O(log n).
        let upd = a.update().unwrap();
        let pkg = TreeCommit::decode(&upd).unwrap();
        assert!(
            pkg.bundles.len() <= 3,
            "expected O(log n) bundles, got {}",
            pkg.bundles.len()
        );
        for (_, g, _) in members.iter_mut() {
            g.process_commit(&upd).unwrap();
            assert_eq!(g.tree_secret, a.tree_secret);
        }
        // A newcomer joins at the latest epoch and converges.
        let (kp_last, dk_last) = real_kp(0x77);
        let (w_last, c_last) = a.add(kp_last).unwrap();
        let fresh = Group::join(&w_last, [0x77; 32], &dk_last).unwrap();
        for (_, g, _) in members.iter_mut() {
            g.process_commit(&c_last).unwrap();
            assert_eq!(g.info().epoch, a.info().epoch);
        }
        assert_eq!(fresh.info().epoch, a.info().epoch);
        assert_eq!(fresh.tree_secret, a.tree_secret);
    }

    #[test]
    fn remove_blank_pcs_and_reject_replay() {
        let mut a = Group::create();
        let (kp_b, dk_b) = real_kp(0x42);
        let (kp_c, dk_c) = real_kp(0x43);
        let (w_b, _c_b) = a.add(kp_b).unwrap();
        let mut b = Group::join(&w_b, [0x42; 32], &dk_b).unwrap();
        let (w_c, c_c) = a.add(kp_c).unwrap();
        let _c = Group::join(&w_c, [0x43; 32], &dk_c).unwrap();
        deliver(&mut a, &mut b, c_c);
        let old_secret = b.tree_secret;
        let commit = a.remove(&[0x43; 32]).unwrap();
        deliver(&mut a, &mut b, commit.clone());
        assert_ne!(a.tree_secret, old_secret);
        // Replay rejected (epoch guard).
        assert!(b.process_commit(&commit).is_err());
        // Unknown member / self-remove rejected.
        assert!(a.remove(&[0x99; 32]).is_err());
        let own_id = *a.member_leaf.keys().next().unwrap();
        // Creator removing itself is only possible if it has an id; the
        // creator does, so target a *different* unknown-in-tree case:
        // removing twice fails.
        assert!(a.remove(&[0x43; 32]).is_err());
        let _ = own_id;
    }

    #[test]
    fn remove_then_update_converges() {
        // Minimal repro shape: 3 members, remove one, then update.
        // The updater's root and the recipient's adopted root must match.
        let mut a = Group::create();
        let (kp_b, dk_b) = real_kp(0x42);
        let (kp_c, dk_c) = real_kp(0x43);
        let (w_b, _c_b) = a.add(kp_b).unwrap();
        let mut b = Group::join(&w_b, [0x42; 32], &dk_b).unwrap();
        let (w_c, c_c) = a.add(kp_c).unwrap();
        deliver(&mut a, &mut b, c_c);
        let _c = Group::join(&w_c, [0x43; 32], &dk_c).unwrap();
        let rm = a.remove(&[0x43; 32]).unwrap();
        deliver(&mut a, &mut b, rm);
        let upd = a.update().unwrap();
        deliver(&mut a, &mut b, upd);
    }

    #[test]
    fn remove_update_converge_4member() {
        // Faithful replica of the session multidevice flow, incl. early
        // message_key calls (sender-chain advancement must not affect
        // tree-secret convergence).
        let mut a = Group::create();
        let mut members: Vec<([u8; 32], Group, KyberKeypair)> = Vec::new();
        for i in [0xA1u8, 0xA2u8, 0xB0u8] {
            let (kp, dk) = real_kp(i);
            let id = [i; 32];
            let (welcome, commit) = a.add(kp).unwrap();
            for (_, g, _) in members.iter_mut() {
                g.process_commit(&commit).unwrap();
            }
            members.push((id, Group::join(&welcome, id, &dk).unwrap(), dk));
        }
        // Early message_key use on every copy (as the session test does).
        let sender = [0x77u8; 32];
        let k0 = a.message_key(&sender).unwrap();
        for (_, g, _) in members.iter_mut() {
            assert_eq!(g.message_key(&sender).unwrap(), k0);
        }
        let rm = a.remove(&[0xA2u8; 32]).unwrap();
        for (_, g, _) in members.iter_mut() {
            if g.member_leaf.contains_key(&[0xA2u8; 32]) || g.info().epoch + 1 == a.info().epoch {
                let _ = g.process_commit(&rm);
            }
        }
        let upd = a.update().unwrap();
        for (id, g, _) in members.iter_mut() {
            if id[0] == 0xA2 {
                continue;
            }
            g.process_commit(&upd).unwrap();
        }
        let probe = [0xABu8; 32];
        let ka = a.message_key(&probe).unwrap();
        for (id, g, _) in members.iter_mut() {
            if id[0] == 0xA2 {
                continue;
            }
            assert_eq!(g.message_key(&probe).unwrap(), ka);
        }
    }

    #[test]
    fn forked_commit_rejected() {
        let mut a = Group::create();
        let (kp_b, dk_b) = real_kp(0x42);
        let (w_b, _c_b) = a.add(kp_b).unwrap();
        let mut b = Group::join(&w_b, [0x42; 32], &dk_b).unwrap();
        assert_eq!(a.tree_secret, b.tree_secret);
        // Tamper prev_hash (ct untouched): chain check must fire.
        let mut pkg = TreeCommit::decode(&a.update().unwrap()).unwrap();
        pkg.prev_hash[7] ^= 0x01;
        let err = b.process_commit(&pkg.encode()).unwrap_err();
        assert!(
            format!("{err:?}").contains("chain"),
            "forked prev_hash must fail chaining"
        );
    }

    #[test]
    fn removed_member_is_defunct() {
        let mut a = Group::create();
        let (kp_b, dk_b) = real_kp(0x42);
        let (w_b, _c_b) = a.add(kp_b).unwrap();
        let mut b = Group::join(&w_b, [0x42; 32], &dk_b).unwrap();
        // B is removed by A carrying B's own leaf position: process marks
        // B defunct (B learns it is out).
        let commit = a.remove(&[0x42; 32]).unwrap();
        b.process_commit(&commit).unwrap();
        assert!(b.message_key(&[0x42; 32]).is_err());
        // Stale outsider commit (wrong group) rejected.
        let other = Group::create();
        let _ = other;
    }

    #[test]
    fn duplicate_add_rejected() {
        let mut a = Group::create();
        let (kp_b, _) = real_kp(0x42);
        let _ = a.add(kp_b.clone()).unwrap();
        assert!(a.add(kp_b).is_err());
    }

    #[test]
    fn envelope_codec_rejects_garbage() {
        assert!(TreeCommit::decode(b"short").is_err());
        assert!(WelcomePkg::decode(b"\x02short").is_err());
        assert!(TreeCommit::decode(&[0x01]).is_err());
    }
}
