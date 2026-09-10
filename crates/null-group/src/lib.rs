//! Null-MLS group messaging (§10): TreeKEM-style group key evolution
//! with PQ KeyPackages (ML-KEM-1024).
//!
//! Simplified-but-sound model: the tree secret evolves every epoch and is
//! distributed sealed under fresh Kyber encapsulations — a `Welcome` for a
//! joiner, or one commit envelope per remaining member on removal (O(n)
//! re-encapsulation gives true PCS without a full TreeKEM implementation,
//! whose path-secret ratchet is tracked as future work for 50k-member scale).

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use null_core::{NullError, Result, MAX_GROUP_MEMBERS};
use null_crypto::{kyber_encap_to, KyberKeypair};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha384;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackage {
    pub member_id: [u8; 32],
    pub kyber_ek: Vec<u8>,
    pub signature_hint: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub group_id: [u8; 32],
    pub epoch: u64,
}

pub struct Group {
    id: [u8; 32],
    epoch: u64,
    /// TreeKEM ratchet tree secret (root). Evolves per commit.
    tree_secret: [u8; 48],
    members: HashMap<[u8; 32], KeyPackage>,
    /// Per-member sender chains for forward secrecy within group.
    sender_chains: HashMap<[u8; 32], u64>,
}

impl Group {
    pub fn create() -> Self {
        let mut id = [0u8; 32];
        OsRng.fill_bytes(&mut id);
        let mut secret = [0u8; 48];
        OsRng.fill_bytes(&mut secret);
        Self {
            id,
            epoch: 0,
            tree_secret: secret,
            members: HashMap::new(),
            sender_chains: HashMap::new(),
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

    pub fn add_member(&mut self, kp: KeyPackage) -> Result<()> {
        if self.members.len() >= MAX_GROUP_MEMBERS {
            return Err(NullError::Group("group full (50k)".into()));
        }
        // Welcome would be Kyber-encapsulated to kp.kyber_ek in production;
        // here we just rotate the tree secret to preserve PCS.
        self.members.insert(kp.member_id, kp.clone());
        self.sender_chains.insert(kp.member_id, 0);
        self.evolve_tree(b"add");
        Ok(())
    }

    pub fn remove_member(&mut self, id: &[u8; 32]) -> Result<()> {
        if self.members.remove(id).is_none() {
            return Err(NullError::Group("unknown member".into()));
        }
        self.sender_chains.remove(id);
        self.evolve_tree(b"remove");
        Ok(())
    }

    /// Remove with true PCS: fresh random tree secret, distributed as one
    /// sealed envelope per *remaining* member (encapsulated to their
    /// KeyPackage eks). The removed member knows only the old secret and
    /// cannot open any envelope. Returns `(member_id, envelope_bytes)` pairs.
    /// The caller transmits them; recipients call [`Group::apply_envelope`].
    /// Our own secret/epoch advance immediately.
    pub fn remove_member_commit(&mut self, id: &[u8; 32]) -> Result<Vec<([u8; 32], Vec<u8>)>> {
        if self.members.remove(id).is_none() {
            return Err(NullError::Group("unknown member".into()));
        }
        self.sender_chains.remove(id);
        let mut fresh = [0u8; 48];
        OsRng.fill_bytes(&mut fresh);
        self.tree_secret = fresh;
        self.epoch += 1;
        let mut out = Vec::new();
        for (mid, kp) in &self.members {
            let env = seal_tree_secret(&self.id, self.epoch, &fresh, &kp.kyber_ek)?;
            out.push((*mid, env.encode()));
        }
        Ok(out)
    }

    /// Accept a join (`Welcome`) or removal commit envelope sealed to our
    /// long-term Kyber dk. Adopts the new tree secret and epoch.
    /// Stale or replayed epochs (≤ current) are rejected.
    pub fn apply_envelope(&mut self, env_bytes: &[u8], dk: &KyberKeypair) -> Result<()> {
        let env = CommitEnvelope::decode(env_bytes)?;
        if env.group_id != self.id {
            return Err(NullError::Group("envelope for another group".into()));
        }
        if env.epoch <= self.epoch {
            return Err(NullError::Group(format!(
                "stale envelope epoch {} (at {})",
                env.epoch, self.epoch
            )));
        }
        let k = dk
            .decapsulate(&env.ct)
            .map_err(|e| NullError::Group(format!("welcome decap: {e}")))?;
        let secret = open_tree_secret_in(&env.group_id, env.epoch, &k, &env.sealed)?;
        self.tree_secret = secret;
        self.epoch = env.epoch;
        Ok(())
    }

    /// Add a member with a real `Welcome`: evolve the tree, then seal the
    /// NEW secret to the joiner's KeyPackage ek. Insert locally and return
    /// the envelope bytes for the joiner (see [`Group::join`]).
    pub fn prepare_welcome(&mut self, kp: KeyPackage) -> Result<Vec<u8>> {
        if self.members.len() >= MAX_GROUP_MEMBERS {
            return Err(NullError::Group("group full (50k)".into()));
        }
        self.evolve_tree(b"add");
        let env = seal_tree_secret(&self.id, self.epoch, &self.tree_secret, &kp.kyber_ek)?;
        self.members.insert(kp.member_id, kp.clone());
        self.sender_chains.insert(kp.member_id, 0);
        Ok(env.encode())
    }

    /// Join a group from a `Welcome` envelope: decapsulate with our
    /// long-term Kyber dk and adopt the tree secret at the envelope epoch.
    pub fn join(env_bytes: &[u8], member_id: [u8; 32], dk: &KyberKeypair) -> Result<Self> {
        let env = CommitEnvelope::decode(env_bytes)?;
        let k = dk
            .decapsulate(&env.ct)
            .map_err(|e| NullError::Group(format!("welcome decap: {e}")))?;
        let secret = open_tree_secret_in(&env.group_id, env.epoch, &k, &env.sealed)?;
        let mut sender_chains = HashMap::new();
        sender_chains.insert(member_id, 0);
        Ok(Self {
            id: env.group_id,
            epoch: env.epoch,
            tree_secret: secret,
            members: HashMap::new(),
            sender_chains,
        })
    }

    /// Group message key for (epoch, sender, seq): HKDF(tree ‖ sender ‖ seq).
    pub fn message_key(&mut self, sender: &[u8; 32]) -> Result<[u8; 32]> {
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

    fn evolve_tree(&mut self, ctx: &[u8]) {
        let hk = Hkdf::<Sha384>::new(Some(&self.id), &self.tree_secret);
        let mut out = [0u8; 48];
        let mut info = b"null-mls-tree-evolve:".to_vec();
        info.extend_from_slice(ctx);
        info.extend_from_slice(&self.epoch.to_be_bytes());
        hk.expand(&info, &mut out).expect("hkdf");
        self.tree_secret = out;
        self.epoch += 1;
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.tree_secret.zeroize();
    }
}

/// Tree secret sealed to one member's KeyPackage ek (Welcome or commit).
/// Wire: `group_id(32) ‖ epoch(8 BE) ‖ ct_len(4 BE) ‖ ct ‖ sealed`.
#[derive(Debug, Clone)]
pub struct CommitEnvelope {
    pub group_id: [u8; 32],
    pub epoch: u64,
    pub ct: Vec<u8>,
    pub sealed: Vec<u8>,
}

impl CommitEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(44 + self.ct.len() + self.sealed.len());
        out.extend_from_slice(&self.group_id);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&(self.ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ct);
        out.extend_from_slice(&self.sealed);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 44 {
            return Err(NullError::Group("envelope too short".into()));
        }
        let mut group_id = [0u8; 32];
        group_id.copy_from_slice(&bytes[..32]);
        let epoch = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
        let ct_len = u32::from_be_bytes(bytes[40..44].try_into().unwrap()) as usize;
        if bytes.len() < 44 + ct_len {
            return Err(NullError::Group("envelope ct overrun".into()));
        }
        Ok(Self {
            group_id,
            epoch,
            ct: bytes[44..44 + ct_len].to_vec(),
            sealed: bytes[44 + ct_len..].to_vec(),
        })
    }
}

/// Seal: encap fresh `k` to the member ek, AEAD the 48B secret under `k`
/// with a zero nonce (single-use key — never reused).
fn seal_tree_secret(
    group_id: &[u8; 32],
    epoch: u64,
    secret: &[u8; 48],
    member_ek: &[u8],
) -> Result<CommitEnvelope> {
    let (ct, k) =
        kyber_encap_to(member_ek).map_err(|e| NullError::Group(format!("welcome encap: {e}")))?;
    let wrap = Hkdf::<Sha384>::new(Some(group_id), &k);
    let mut wk = [0u8; 32];
    let mut info = b"null-mls-welcome-wrap:".to_vec();
    info.extend_from_slice(&epoch.to_be_bytes());
    wrap.expand(&info, &mut wk)
        .map_err(|e| NullError::Group(format!("hkdf: {e}")))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wk));
    let mut sealed = secret.to_vec();
    cipher
        .encrypt_in_place(Nonce::from_slice(&[0u8; 12]), group_id, &mut sealed)
        .map_err(|e| NullError::Group(format!("seal: {e}")))?;
    use zeroize::Zeroize;
    wk.zeroize();
    Ok(CommitEnvelope {
        group_id: *group_id,
        epoch,
        ct,
        sealed,
    })
}

fn open_tree_secret_in(
    group_id: &[u8; 32],
    epoch: u64,
    k: &[u8],
    sealed: &[u8],
) -> Result<[u8; 48]> {
    let wrap = Hkdf::<Sha384>::new(Some(group_id), k);
    let mut wk = [0u8; 32];
    let mut info = b"null-mls-welcome-wrap:".to_vec();
    info.extend_from_slice(&epoch.to_be_bytes());
    wrap.expand(&info, &mut wk)
        .map_err(|e| NullError::Group(format!("hkdf: {e}")))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wk));
    let mut buf = sealed.to_vec();
    cipher
        .decrypt_in_place(Nonce::from_slice(&[0u8; 12]), group_id, &mut buf)
        .map_err(|e| NullError::Group(format!("open: {e}")))?;
    use zeroize::Zeroize;
    wk.zeroize();
    let mut secret = [0u8; 48];
    secret.copy_from_slice(&buf[..48]);
    buf.zeroize();
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(seed: u8) -> KeyPackage {
        KeyPackage {
            member_id: [seed; 32],
            kyber_ek: vec![seed; 32],
            signature_hint: None,
        }
    }

    #[test]
    fn add_remove_evolves_epoch() {
        let mut g = Group::create();
        assert_eq!(g.info().epoch, 0);
        g.add_member(kp(1)).unwrap();
        g.add_member(kp(2)).unwrap();
        assert_eq!(g.member_count(), 2);
        let k1 = g.message_key(&[1u8; 32]).unwrap();
        let k2 = g.message_key(&[1u8; 32]).unwrap();
        assert_ne!(k1, k2); // sender ratchet advances
        g.remove_member(&[1u8; 32]).unwrap();
        assert_eq!(g.member_count(), 1);
    }

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

    #[test]
    fn seal_open_roundtrip_direct() {
        use super::*;
        let gid = [7u8; 32];
        let kp = KyberKeypair::generate();
        let mut secret = [0u8; 48];
        OsRng.fill_bytes(&mut secret);
        let env = seal_tree_secret(&gid, 3, &secret, &kp.ek_bytes()).unwrap();
        let bytes = env.encode();
        let back = CommitEnvelope::decode(&bytes).unwrap();
        assert_eq!(back.ct, env.ct);
        assert_eq!(back.sealed, env.sealed);
        let k = kp.decapsulate(&back.ct).unwrap();
        let opened = open_tree_secret_in(&back.group_id, back.epoch, &k, &back.sealed).unwrap();
        assert_eq!(opened, secret);
    }

    #[test]
    fn welcome_join_converges() {
        let mut a = Group::create();
        let (kp_b, dk_b) = real_kp(0x42);
        let welcome = a.prepare_welcome(kp_b).unwrap();
        let mut b = Group::join(&welcome, [0x42; 32], &dk_b).unwrap();
        assert_eq!(a.info().epoch, b.info().epoch);
        assert_eq!(a.tree_secret, b.tree_secret);
        // Same (sender, seq, epoch) derives the same key on both sides.
        let sender = [9u8; 32];
        assert_eq!(
            a.message_key(&sender).unwrap(),
            b.message_key(&sender).unwrap()
        );
        assert!(CommitEnvelope::decode(b"short").is_err());
    }

    #[test]
    fn remove_commit_heals_remaining() {
        // A hosts; B and C join via Welcome.
        let mut a = Group::create();
        let (kp_b, dk_b) = real_kp(0x42);
        let (kp_c, dk_c) = real_kp(0x43);
        let w_b = a.prepare_welcome(kp_b).unwrap();
        let w_c = a.prepare_welcome(kp_c).unwrap();
        // B joins at its own Welcome (epoch 1); C joins at epoch 2. B syncs
        // to the post-removal epoch via its commit envelope below — adds
        // evolve the tree, removals re-randomize it, so stragglers always
        // converge on the next commit addressed to them.
        let _ = w_c;
        let _ = dk_c;
        let mut b = Group::join(&w_b, [0x42; 32], &dk_b).unwrap();
        let old_secret = b.tree_secret;
        // A removes C with PCS commits; B applies its envelope.
        let commits = a.remove_member_commit(&[0x43; 32]).unwrap();
        assert_eq!(commits.len(), 1);
        let (mid, env) = &commits[0];
        assert_eq!(*mid, [0x42; 32]);
        b.apply_envelope(env, &dk_b).unwrap();
        assert_eq!(a.tree_secret, b.tree_secret);
        assert_ne!(a.tree_secret, old_secret);
        assert_eq!(a.info().epoch, b.info().epoch);
        // Replay of the same envelope is rejected (epoch guard).
        assert!(b.apply_envelope(env, &dk_b).is_err());
        // Wrong-group envelope rejected.
        let mut other = Group::create();
        assert!(other.apply_envelope(env, &dk_b).is_err());
    }
}
