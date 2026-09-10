//! Ratchet tree (§10, TreeKEM-style): O(log n) path commits.
//!
//! Complete binary tree in heap indexing (root = 0). Leaves hold members;
//! internal nodes hold ML-KEM node keypairs derived deterministically from
//! path secrets, so every member derives the same public tree without
//! exchanging private material. Removals blank nodes; encryption targets a
//! sibling subtree's *resolution* (minimal non-blank cover), giving O(log n)
//! ciphertexts per commit instead of one per member.

use hkdf::Hkdf;
use null_core::{NullError, Result};
use null_crypto::{kyber_encap_to, KyberKeypair};
use sha2::Sha384;
use std::collections::{HashMap, HashSet};

fn parent(i: u32) -> Option<u32> {
    if i == 0 {
        None
    } else {
        Some((i - 1) / 2)
    }
}

fn left_child(i: u32) -> u32 {
    2 * i + 1
}

fn right_child(i: u32) -> u32 {
    2 * i + 2
}

fn sibling(i: u32) -> Option<u32> {
    if i == 0 {
        None
    } else if i % 2 == 1 {
        Some(i + 1)
    } else {
        Some(i - 1)
    }
}

fn kdf_node(ps: &[u8; 32]) -> [u8; 64] {
    let hk = Hkdf::<Sha384>::new(None, ps);
    let mut out = [0u8; 64];
    hk.expand(b"null-mls-node", &mut out).expect("hkdf");
    out
}

fn kdf_path(ps: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha384>::new(None, ps);
    let mut out = [0u8; 32];
    hk.expand(b"null-mls-path", &mut out).expect("hkdf");
    out
}

fn kdf_root(ps: &[u8; 32]) -> [u8; 48] {
    let hk = Hkdf::<Sha384>::new(None, ps);
    let mut out = [0u8; 48];
    hk.expand(b"null-mls-root", &mut out).expect("hkdf");
    out
}

/// Wrap a 32B path secret for one resolution node: encap to its ek, then
/// AEAD under the shared secret. Returns `(ct, sealed)`.
pub fn seal_path_secret(ps: &[u8; 32], member_ek: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
    let (ct, k) =
        kyber_encap_to(member_ek).map_err(|e| NullError::Group(format!("path encap: {e}")))?;
    let wrap = Hkdf::<Sha384>::new(None, &k);
    let mut wk = [0u8; 32];
    wrap.expand(b"null-mls-path-wrap", &mut wk)
        .map_err(|e| NullError::Group(format!("hkdf: {e}")))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wk));
    let mut sealed = ps.to_vec();
    cipher
        .encrypt_in_place(Nonce::from_slice(&[0u8; 12]), b"null-mls-path", &mut sealed)
        .map_err(|e| NullError::Group(format!("seal: {e}")))?;
    use zeroize::Zeroize;
    wk.zeroize();
    Ok((ct, sealed))
}

/// Open a sealed path secret with the target node's decapsulation key.
pub fn open_path_secret(dk: &KyberKeypair, ct: &[u8], sealed: &[u8]) -> Result<[u8; 32]> {
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
    let k = dk
        .decapsulate(ct)
        .map_err(|e| NullError::Group(format!("path decap: {e}")))?;
    let wrap = Hkdf::<Sha384>::new(None, &k);
    let mut wk = [0u8; 32];
    wrap.expand(b"null-mls-path-wrap", &mut wk)
        .map_err(|e| NullError::Group(format!("hkdf: {e}")))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wk));
    let mut buf = sealed.to_vec();
    cipher
        .decrypt_in_place(Nonce::from_slice(&[0u8; 12]), b"null-mls-path", &mut buf)
        .map_err(|e| NullError::Group(format!("open: {e}")))?;
    use zeroize::Zeroize;
    wk.zeroize();
    if buf.len() != 32 {
        // decrypt_in_place strips the 16B Poly1305 tag: 32B secret remains.
        return Err(NullError::Group("bad sealed length".into()));
    }
    let mut ps = [0u8; 32];
    ps.copy_from_slice(&buf[..32]);
    buf.zeroize();
    Ok(ps)
}

/// Ratchet tree state for ONE member: full public keys plus private seeds
/// for the nodes on its own path (and its leaf decapsulation key).
#[derive(Clone)]
pub struct RatchetTree {
    depth: u32,
    /// Blank node indices (never carry keys).
    blanks: HashSet<u32>,
    /// Occupied leaf positions.
    occupied: HashSet<u32>,
    /// Public Kyber eks for every non-blank node.
    pubs: HashMap<u32, Vec<u8>>,
    /// Private node seeds for nodes on our path (index → 64B seed).
    own_seeds: HashMap<u32, [u8; 64]>,
    /// Our leaf's decapsulation key. `None` once our leaf secret is a
    /// derived seed (present in `own_seeds` instead).
    leaf_dk: Option<KyberKeypair>,
    /// Our leaf position.
    pub own_leaf: u32,
}

impl RatchetTree {
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// This member's leaf position.
    pub fn own_leaf_pos(&self) -> u32 {
        self.own_leaf
    }

    pub fn occupied_count(&self) -> u32 {
        self.occupied.len() as u32
    }

    /// Public ek of a leaf position (its KeyPackage-time or evolved key).
    pub fn leaf_ek(&self, pos: u32) -> Option<Vec<u8>> {
        self.pubs.get(&self.leaf_node(pos)).cloned()
    }

    /// Mark a leaf position occupied (fresh joins) and unblank its node.
    pub(crate) fn occupy(&mut self, pos: u32) {
        self.occupied.insert(pos);
        self.blanks.remove(&self.leaf_node(pos));
    }

    /// Record a public key for a node (fresh keys, merges, joins).
    pub(crate) fn set_keyed(&mut self, idx: u32, ek: Vec<u8>) {
        self.blanks.remove(&idx);
        self.pubs.insert(idx, ek);
    }

    /// Adopt a path node secret (joiner path from Welcome).
    pub(crate) fn adopt_node(&mut self, idx: u32, seed: [u8; 64]) {
        self.blanks.remove(&idx);
        self.own_seeds.insert(idx, seed);
    }

    /// Set our leaf position + long-term decapsulation key (join).
    pub(crate) fn set_own_leaf(&mut self, pos: u32, dk: Option<KyberKeypair>) {
        self.own_leaf = pos;
        self.leaf_dk = dk;
    }

    pub fn leaf_count(&self) -> u32 {
        1 << self.depth
    }

    fn total_nodes(&self) -> u32 {
        2 * self.leaf_count() - 1
    }

    pub fn leaf_node(&self, pos: u32) -> u32 {
        (self.leaf_count() - 1) + pos
    }

    fn in_bounds(&self, idx: u32) -> bool {
        idx < self.total_nodes()
    }

    /// Empty tree at a given depth (join target): all blank, no keys.
    /// The caller adopts pubs, blanks, path seeds and the leaf position.
    pub(crate) fn empty_at(depth: u32) -> Self {
        Self {
            depth,
            blanks: HashSet::new(),
            occupied: HashSet::new(),
            pubs: HashMap::new(),
            own_seeds: HashMap::new(),
            leaf_dk: None,
            own_leaf: 0,
        }
    }

    /// Fresh single-member tree: random leaf seed, no blanks.
    pub fn single() -> (Self, [u8; 48]) {
        use rand::{rngs::OsRng, RngCore};
        let mut seed = [0u8; 64];
        OsRng.fill_bytes(&mut seed);
        let pair = KyberKeypair::generate_deterministic(&seed);
        let mut pubs = HashMap::new();
        pubs.insert(0, pair.ek_bytes());
        let mut own_seeds = HashMap::new();
        own_seeds.insert(0, seed);
        // Depth-0 tree: the root IS the leaf; the root secret derives from
        // the leaf seed (joiners adopt it via Welcome, so all agree).
        let root_secret = {
            let hk = Hkdf::<Sha384>::new(None, &seed);
            let mut out = [0u8; 48];
            hk.expand(b"null-mls-root", &mut out).expect("hkdf");
            out
        };
        (
            Self {
                depth: 0,
                blanks: HashSet::new(),
                occupied: HashSet::from([0]),
                pubs,
                own_seeds,
                leaf_dk: None,
                own_leaf: 0,
            },
            root_secret,
        )
    }

    /// Path from a node up to (and including) the root.
    pub(crate) fn path_to_root(&self, mut idx: u32) -> Vec<u32> {
        let mut path = vec![idx];
        while let Some(p) = parent(idx) {
            path.push(p);
            idx = p;
        }
        path
    }

    /// Tree depth of a node index (root = 0).
    pub(crate) fn node_depth(&self, mut idx: u32) -> u32 {
        let mut d = 0;
        while let Some(p) = parent(idx) {
            d += 1;
            idx = p;
        }
        d
    }

    /// Depth of the lowest common ancestor of two leaf positions.
    pub(crate) fn lca_depth(&self, a_pos: u32, b_pos: u32) -> u32 {
        let a_set: HashSet<u32> = self
            .path_to_root(self.leaf_node(a_pos))
            .into_iter()
            .collect();
        let mut b = self.leaf_node(b_pos);
        loop {
            if a_set.contains(&b) {
                return self.node_depth(b);
            }
            b = parent(b).expect("root is a common ancestor");
        }
    }

    /// Minimal non-blank cover of the subtree under `idx`.
    pub fn resolution(&self, idx: u32) -> Vec<u32> {
        if !self.in_bounds(idx) || self.blanks.contains(&idx) {
            if !self.in_bounds(idx) {
                return vec![];
            }
            if self.is_leaf_idx(idx) {
                return vec![];
            }
            let mut out = self.resolution(left_child(idx));
            out.extend(self.resolution(right_child(idx)));
            return out;
        }
        vec![idx]
    }

    fn is_leaf_idx(&self, idx: u32) -> bool {
        idx >= self.leaf_count() - 1
    }

    /// Double the tree: old tree becomes the left subtree (indices remap
    /// `i → 2i+1`), right subtree starts fully blank. Deterministic — every
    /// member applying the same commit grows identically.
    ///
    /// Heap doubling does NOT preserve dense leaf positions (old position 1
    /// lands on new position 2); returns the `(old_pos, new_pos)` remap for
    /// occupied leaves so roster maps stay exact.
    pub fn grow(&mut self) -> Vec<(u32, u32)> {
        let old_count = self.leaf_count();
        let mut pos_remap = Vec::new();
        for &p in &self.occupied {
            let new_pos = (2 * ((old_count - 1) + p) + 1) - (2 * old_count - 1);
            pos_remap.push((p, new_pos));
        }
        let remap = |i: u32| 2 * i + 1;
        self.blanks = std::mem::take(&mut self.blanks)
            .into_iter()
            .map(remap)
            .collect();
        self.pubs = std::mem::take(&mut self.pubs)
            .into_iter()
            .map(|(i, ek)| (remap(i), ek))
            .collect();
        self.own_seeds = std::mem::take(&mut self.own_seeds)
            .into_iter()
            .map(|(i, s)| (remap(i), s))
            .collect();
        self.depth += 1;
        // Refresh occupancy + own position through the remap.
        let mut new_occupied = HashSet::new();
        for (_, np) in &pos_remap {
            new_occupied.insert(*np);
        }
        self.occupied = new_occupied;
        if let Some((_, np)) = pos_remap.iter().find(|(op, _)| *op == self.own_leaf) {
            self.own_leaf = *np;
        }
        // Fresh nodes are exactly the even indices (old nodes all remapped
        // odd) plus the new unoccupied leaves: all start blank.
        let total = self.total_nodes();
        for i in (0..total).step_by(2) {
            self.blanks.insert(i);
            self.pubs.remove(&i);
        }
        for pos in 0..self.leaf_count() {
            if !self.occupied.contains(&pos) {
                self.blanks.insert(self.leaf_node(pos));
            }
        }
        pos_remap
    }

    /// Smallest free leaf position, if any. Growth (which renumbers
    /// positions) is the caller's job so roster maps stay exact — see
    /// [`Group::add`][crate::Group::add].
    pub fn alloc_leaf(&mut self) -> Option<u32> {
        let pos = (0..self.leaf_count()).find(|p| !self.occupied.contains(p))?;
        self.occupied.insert(pos);
        self.blanks.remove(&self.leaf_node(pos));
        Some(pos)
    }

    /// Vacate a leaf position (removal); the leaf node goes blank.
    pub fn vacate_leaf(&mut self, pos: u32) {
        self.occupied.remove(&pos);
        let node = self.leaf_node(pos);
        self.blanks.insert(node);
        self.pubs.remove(&node);
    }

    /// Committer-side path update: fresh secrets for our whole direct path.
    ///
    /// Returns `(updated_pubs, bundles, root_secret, level_seeds)` where
    /// `bundles` holds `(target_idx, ct, sealed)` per resolution node and
    /// `level_seeds[k]` is the node seed for committer level `k`
    /// (level 0 = our leaf). Applies locally.
    #[allow(clippy::type_complexity)]
    pub fn commit_path(
        &mut self,
        fresh: [u8; 32],
    ) -> Result<(
        Vec<(u32, Vec<u8>)>,
        Vec<(u32, Vec<u8>, Vec<u8>)>,
        [u8; 48],
        Vec<[u8; 64]>,
    )> {
        let leaf_node = self.leaf_node(self.own_leaf);
        let path = self.path_to_root(leaf_node);
        let d = self.depth as usize;
        debug_assert_eq!(path.len(), d + 1);
        let mut updated = Vec::new();
        let mut bundles = Vec::new();
        let mut level_seeds = Vec::with_capacity(d + 1);
        let mut ps = fresh;
        for node in path.iter().take(d) {
            let seed = kdf_node(&ps);
            let pair = KyberKeypair::generate_deterministic(&seed);
            // Publish ( drained blanks on our path: we now key them).
            self.blanks.remove(node);
            self.pubs.insert(*node, pair.ek_bytes());
            self.own_seeds.insert(*node, seed);
            updated.push((*node, pair.ek_bytes()));
            level_seeds.push(seed);
            // Encrypt ps[k] to the sibling subtree's resolution.
            if let Some(sib) = sibling(*node) {
                for target in self.resolution(sib) {
                    let ek = self.pubs.get(&target).ok_or_else(|| {
                        NullError::Group(format!("missing pub for resolution node {target}"))
                    })?;
                    let (ct, sealed) = seal_path_secret(&ps, ek)?;
                    bundles.push((target, ct, sealed));
                }
            }
            ps = kdf_path(&ps);
        }
        // Our leaf pair now derives from its node seed (depth ≥ 1 always
        // carries the leaf in the loop above; depth-0 solo keeps its seed).
        if d >= 1 {
            self.leaf_dk = None;
        }
        let root_secret = kdf_root(&ps);
        Ok((updated, bundles, root_secret, level_seeds))
    }

    /// Merge remote public keys + blanks (drops our secrets for blanked
    /// nodes on our own path — resolution routes around blanks).
    pub fn merge_public(&mut self, updated: &[(u32, Vec<u8>)], blanked: &[u32]) {
        for idx in blanked {
            self.blanks.insert(*idx);
            self.pubs.remove(idx);
            self.own_seeds.remove(idx);
        }
        for (idx, ek) in updated {
            self.blanks.remove(idx);
            self.pubs.insert(*idx, ek.clone());
        }
    }

    /// Open the bundle addressed to our subtree (if any) using a node secret
    /// on our own path. Returns `(committer_level, path_secret)`: the level
    /// `k` such that the bundle carries the committer's `ps[k]`.
    ///
    /// The target sits in the sibling subtree of the committer's level-`k`
    /// node, so climbing from the target until we hit the committer path
    /// lands on the level-`k+1` node; `k` is one less than its position.
    pub fn open_bundle(
        &self,
        bundles: &[(u32, Vec<u8>, Vec<u8>)],
        committer_leaf_pos: u32,
    ) -> Result<(usize, [u8; 32])> {
        let committer_node = self.leaf_node(committer_leaf_pos);
        let committer_path = self.path_to_root(committer_node);
        for (target, ct, sealed) in bundles {
            let dk = if Some(*target) == self.leaf_node_checked() {
                self.leaf_pair()?
            } else if let Some(seed) = self.own_seeds.get(target) {
                KyberKeypair::generate_deterministic(seed)
            } else {
                continue;
            };
            if let Ok(ps) = open_path_secret(&dk, ct, sealed) {
                let mut climb = *target;
                loop {
                    if committer_path.contains(&climb) {
                        let pos = committer_path
                            .iter()
                            .position(|n| *n == climb)
                            .expect("contained");
                        if pos == 0 {
                            // Target is on the committer path itself: only
                            // possible for our own redelivered commit.
                            return Err(NullError::Group("bundle targets committer path".into()));
                        }
                        return Ok((pos - 1, ps));
                    }
                    climb = parent(climb)
                        .ok_or_else(|| NullError::Group("bundle outside committer path".into()))?;
                }
            }
        }
        Err(NullError::Group(
            "no bundle openable with our path secrets".into(),
        ))
    }

    fn leaf_node_checked(&self) -> Option<u32> {
        Some(self.leaf_node(self.own_leaf))
    }

    fn leaf_pair(&self) -> Result<KyberKeypair> {
        if let Some(seed) = self.own_seeds.get(&self.leaf_node(self.own_leaf)) {
            return Ok(KyberKeypair::generate_deterministic(seed));
        }
        self.leaf_dk
            .clone()
            .ok_or_else(|| NullError::Group("no leaf key".into()))
    }

    /// Adopt shared path secrets for our own nodes at committer levels
    /// `start..=D`, deriving down from an opened `ps[start-1]`.
    /// Committer level `k` is tree depth `D-k`; our node there is `k` steps
    /// up from our leaf. Returns the root secret. Nodes below the merge
    /// point (our exclusive branch) keep their existing secrets.
    pub fn adopt_shared_path(
        &mut self,
        ps_at_prev: [u8; 32],
        start_level: usize,
    ) -> Result<[u8; 48]> {
        let d = self.depth as usize;
        if start_level == 0 || start_level > d {
            return Err(NullError::Group("shared level out of range".into()));
        }
        let my_leaf_node = self.leaf_node(self.own_leaf);
        let mut ps = ps_at_prev;
        for k in start_level..=d {
            ps = kdf_path(&ps);
            if k < d {
                let mut idx = my_leaf_node;
                for _ in 0..k {
                    idx = parent(idx).expect("path to root");
                }
                if !self.blanks.contains(&idx) {
                    let seed = kdf_node(&ps);
                    self.own_seeds.insert(idx, seed);
                    let pair = KyberKeypair::generate_deterministic(&seed);
                    self.pubs.insert(idx, pair.ek_bytes());
                }
            } else {
                return Ok(kdf_root(&ps));
            }
        }
        Err(NullError::Group("unreachable path adoption".into()))
    }

    /// Blank a set of nodes (removal), dropping our secrets there.
    pub fn apply_blanks(&mut self, blanked: &[u32]) {
        for idx in blanked {
            self.blanks.insert(*idx);
            self.pubs.remove(idx);
            self.own_seeds.remove(idx);
        }
    }

    /// Public keys snapshot for Welcome packages.
    pub fn public_snapshot(&self) -> Vec<(u32, Vec<u8>)> {
        let mut v: Vec<_> = self.pubs.iter().map(|(i, ek)| (*i, ek.clone())).collect();
        v.sort_unstable_by_key(|(i, _)| *i);
        v
    }

    /// Blanks snapshot (sorted) for deterministic packages.
    pub fn blank_snapshot(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.blanks.iter().copied().collect();
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_ps(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn tree_math_basics() {
        let (t, _) = RatchetTree::single();
        assert_eq!(t.depth(), 0);
        assert_eq!(t.leaf_count(), 1);
        assert_eq!(t.path_to_root(0), vec![0]);
        assert_eq!(t.resolution(0), vec![0]);
        // Grow: old root remaps to left child, new root + spine blank.
        let mut t = t;
        t.grow();
        assert_eq!(t.depth(), 1);
        assert_eq!(t.leaf_count(), 2);
        assert!(t.blanks.contains(&0));
        assert!(!t.blanks.contains(&1));
        assert_eq!(t.leaf_node(0), 1);
        assert_eq!(t.leaf_node(1), 2);
        assert_eq!(t.resolution(0), vec![1]);
        assert_eq!(t.resolution(2), vec![]);
        assert_eq!(t.path_to_root(2), vec![2, 0]);
    }

    #[test]
    fn solo_commit_has_no_bundles() {
        let (mut t, _) = RatchetTree::single();
        let (updated, bundles, _root, levels) = t.commit_path(fresh_ps(1)).unwrap();
        assert_eq!(updated.len(), 0); // depth 0: no path nodes below root
        assert!(bundles.is_empty());
        assert!(levels.is_empty());
    }

    #[test]
    fn two_member_commit_opens() {
        // A creates (leaf 0), grows, B joins at leaf 1 with long-term pair.
        let (mut ta, root_a) = RatchetTree::single();
        ta.grow();
        let kp_b = KyberKeypair::generate();
        let pos_b = ta.alloc_leaf().unwrap();
        assert_eq!(pos_b, 1);
        // B's tree state mirrors A's public parts + own leaf key.
        let mut tb = ta.clone();
        tb.own_leaf = 1;
        tb.own_seeds.clear();
        tb.leaf_dk = Some(kp_b.clone());
        // A learns B's leaf pub (as via KeyPackage).
        ta.pubs.insert(ta.leaf_node(1), kp_b.ek_bytes());
        tb.pubs.insert(tb.leaf_node(1), kp_b.ek_bytes());
        let _ = root_a;
        // A commits: one bundle to B's leaf.
        let (updated, bundles, root_a2, _) = ta.commit_path(fresh_ps(9)).unwrap();
        assert_eq!(bundles.len(), 1);
        // B merges pubs, opens the bundle, adopts the shared path (root).
        tb.merge_public(&updated, &[]);
        let (level, ps) = tb.open_bundle(&bundles, 0).unwrap();
        assert_eq!(level, 0);
        let root_b2 = tb.adopt_shared_path(ps, level + 1).unwrap();
        assert_eq!(root_a2, root_b2);
    }

    #[test]
    fn blank_resolution_routes_around() {
        let (mut t, _) = RatchetTree::single();
        t.grow();
        t.grow(); // 4 leaves at nodes 3,4,5,6; mids 1,2; root 0
        assert_eq!(t.leaf_count(), 4);
        // Occupy leaf 1 so its node carries a key.
        let pos = t.alloc_leaf().unwrap();
        assert_eq!(pos, 1);
        assert!(!t.blanks.contains(&4));
        // Blank occupied leaf 0: resolution of node 1 routes to leaf 1.
        t.apply_blanks(&[3]);
        assert_eq!(t.resolution(1), vec![4]);
        assert_eq!(t.resolution(0), vec![4]);
        // Blanking the internal node keeps covered leaves reachable.
        t.apply_blanks(&[1]);
        assert_eq!(t.resolution(1), vec![4]);
        assert_eq!(t.resolution(0), vec![4]);
        // Blanking the last live leaf empties the whole tree cover.
        t.apply_blanks(&[4]);
        assert_eq!(t.resolution(0), Vec::<u32>::new());
    }
}
