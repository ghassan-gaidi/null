//! Anonymous update distribution (§9.3): signed manifest fetched over
//! onion / P2P gossip. Hybrid signatures: Ed25519 + SLH-DSA-SHA2-128s
//! (FIPS 205) — both must verify.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use null_core::{NullError, Result};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// FIPS 205 release signatures (SLH-DSA-SHA2-128s, stateless hash-based).
pub mod slh {
    use super::*;
    use signature::Verifier as _;
    use slh_dsa::{Sha2_128s, SigningKey as SlhSk, VerifyingKey as SlhVk};

    /// Release SLH-DSA keypair. Kept in memory only during signing
    /// (tests / release tooling); production verifiers see just the vk.
    pub struct SlhReleaseKey {
        sk: SlhSk<Sha2_128s>,
    }

    impl SlhReleaseKey {
        pub fn generate() -> Self {
            // SLH-DSA-SHA2-128s (N=16): keygen is deterministic over
            // (sk_seed, sk_prf, pk_seed); entropy comes from the OS.
            // (Avoids pinning a second rand-major trait stack.)
            use rand::RngCore;
            let mut seed = [0u8; 48];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            Self {
                sk: SlhSk::slh_keygen_internal(&seed[..16], &seed[16..32], &seed[32..]),
            }
        }

        /// Raw 32B verification key bytes for manifests and transparency logs.
        pub fn verifying_bytes(&self) -> Vec<u8> {
            use signature::Keypair as _;
            self.sk.verifying_key().to_bytes().as_slice().to_vec()
        }

        pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
            use signature::Signer;
            self.sk.sign(msg).to_vec()
        }
    }

    pub fn verify(vk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
        use hybrid_array::{typenum::U32, Array};
        if vk_bytes.len() != 32 {
            return Err(NullError::Update("bad slh vk length".into()));
        }
        let arr = Array::<u8, U32>::try_from(vk_bytes)
            .map_err(|_| NullError::Update("bad slh vk encoding".into()))?;
        let vk = SlhVk::<Sha2_128s>::from(arr);
        let sig = slh_dsa::Signature::<Sha2_128s>::try_from(sig_bytes)
            .map_err(|_| NullError::Update("bad slh sig encoding".into()))?;
        vk.verify(msg, &sig)
            .map_err(|e| NullError::Update(format!("sphincs verify: {e}")))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn slh_roundtrip() {
            let k = SlhReleaseKey::generate();
            let vk = k.verifying_bytes();
            assert_eq!(vk.len(), 32);
            let sig = k.sign(b"release-bytes");
            verify(&vk, b"release-bytes", &sig).unwrap();
            assert!(verify(&vk, b"tampered", &sig).is_err());
            assert!(verify(&vk, b"release-bytes", b"short").is_err());
        }
    }
}

/// Update manifest (§9.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateManifest {
    pub version: u64,
    pub sha3_256_hex: String,
    /// Ed25519 signature over (version ‖ sha3_hex).
    pub ed25519_sig_hex: String,
    /// SLH-DSA-SHA2-128s signature over the same bytes (hex).
    #[serde(default)]
    pub sphincs_sig_hex: String,
    pub cargo_lock_digest_hex: String,
}

impl UpdateManifest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!("{}:{}", self.version, self.sha3_256_hex).into_bytes()
    }

    /// Hybrid verification: Ed25519 AND SLH-DSA must both pass, plus the
    /// monotonic version floor. Either failure rejects the update.
    pub fn verify(&self, vk: &VerifyingKey, vk_slh: &[u8], min_version: u64) -> Result<()> {
        if self.version < min_version {
            return Err(NullError::Downgrade {
                got: self.version,
                min: min_version,
            });
        }
        let sig_bytes = hex_decode(&self.ed25519_sig_hex)?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| NullError::Update("ed25519 sig must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify(&self.signing_bytes(), &sig)
            .map_err(|e| NullError::Update(format!("ed25519 verify: {e}")))?;
        let slh_sig = hex_decode(&self.sphincs_sig_hex)?;
        slh::verify(vk_slh, &self.signing_bytes(), &slh_sig)?;
        Ok(())
    }

    /// Gossip encoding: JSON bytes (framed by the caller's length prefix).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| NullError::Update(format!("encode: {e}")))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 1024 * 1024 {
            return Err(NullError::Update("manifest too large".into()));
        }
        serde_json::from_slice(bytes).map_err(|e| NullError::Update(format!("decode: {e}")))
    }
}

/// Local update state: current version, release key, and the best verified
/// gossip offer seen so far (§9.3). Trust comes from signatures, never from
/// the transport that delivered them.
pub struct UpdateStore {
    release_key: VerifyingKey,
    release_key_slh: Vec<u8>,
    current_version: u64,
    best: Option<(UpdateManifest, Vec<u8>)>,
}

impl UpdateStore {
    pub fn new(release_key: VerifyingKey, release_key_slh: Vec<u8>, current_version: u64) -> Self {
        Self {
            release_key,
            release_key_slh,
            current_version,
            best: None,
        }
    }

    /// Validate a manifest+binary pair from ANY source (onion fetch or peer
    /// gossip). Returns true iff it becomes the new best offer.
    pub fn offer(&mut self, manifest: UpdateManifest, binary: &[u8]) -> Result<bool> {
        manifest.verify(
            &self.release_key,
            &self.release_key_slh,
            self.current_version + 1,
        )?;
        if sha3_256_hex(binary) != manifest.sha3_256_hex {
            return Err(NullError::Update("binary hash mismatch".into()));
        }
        let newer = self
            .best
            .as_ref()
            .map(|(m, _)| manifest.version > m.version)
            .unwrap_or(true);
        if newer {
            self.best = Some((manifest, binary.to_vec()));
        }
        Ok(newer)
    }

    /// Merge one gossip message: `manifest_bytes ‖ 0x00 ‖ binary`.
    /// Malformed or invalid offers are rejected without touching state.
    pub fn merge_gossip(&mut self, msg: &[u8]) -> Result<bool> {
        let split = msg
            .iter()
            .position(|&b| b == 0x00)
            .ok_or_else(|| NullError::Update("gossip framing".into()))?;
        let manifest = UpdateManifest::from_bytes(&msg[..split])?;
        self.offer(manifest, &msg[split + 1..])
    }

    /// Encode our best offer for gossip (None if nothing newer known).
    pub fn gossip_message(&self) -> Option<Vec<u8>> {
        let (m, bin) = self.best.as_ref()?;
        let mut out = m.to_bytes().ok()?;
        out.push(0x00);
        out.extend_from_slice(bin);
        Some(out)
    }

    pub fn best(&self) -> Option<&UpdateManifest> {
        self.best.as_ref().map(|(m, _)| m)
    }

    pub fn needs_update(&self) -> bool {
        self.best.is_some()
    }
}

pub fn sha3_256_hex(data: &[u8]) -> String {
    let mut h = Sha3_256::new();
    h.update(data);
    hex_encode(h.finalize())
}

pub fn sign_manifest(
    sk: &SigningKey,
    sk_slh: &slh::SlhReleaseKey,
    version: u64,
    binary: &[u8],
    cargo_lock: &[u8],
) -> UpdateManifest {
    let sha = sha3_256_hex(binary);
    let mut m = UpdateManifest {
        version,
        sha3_256_hex: sha,
        ed25519_sig_hex: String::new(),
        sphincs_sig_hex: String::new(),
        cargo_lock_digest_hex: sha3_256_hex(cargo_lock),
    };
    let sig = sk.sign(&m.signing_bytes());
    m.ed25519_sig_hex = hex_encode(sig.to_bytes());
    m.sphincs_sig_hex = hex_encode(sk_slh.sign(&m.signing_bytes()));
    m
}

fn hex_encode(b: impl AsRef<[u8]>) -> String {
    b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(h: &str) -> Result<Vec<u8>> {
    if !h.len().is_multiple_of(2) || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(NullError::Update("bad hex".into()));
    }
    (0..h.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&h[i..i + 2], 16).map_err(|e| NullError::Update(format!("hex: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_verify_and_downgrade_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let sk_slh = slh::SlhReleaseKey::generate();
        let vk_slh = sk_slh.verifying_bytes();
        let m = sign_manifest(&sk, &sk_slh, 3, b"binary-bytes", b"lock");
        m.verify(&sk.verifying_key(), &vk_slh, 3).unwrap();
        assert!(m.verify(&sk.verifying_key(), &vk_slh, 4).is_err());
        let other = SigningKey::generate(&mut OsRng);
        assert!(m.verify(&other.verifying_key(), &vk_slh, 1).is_err());
        // PQ-only forgery fails even with a valid classical signature.
        let other_slh = slh::SlhReleaseKey::generate();
        assert!(m
            .verify(&sk.verifying_key(), &other_slh.verifying_bytes(), 1)
            .is_err());
    }

    #[test]
    fn store_accepts_newer_rejects_rest() {
        let sk = SigningKey::generate(&mut OsRng);
        let sk_slh = slh::SlhReleaseKey::generate();
        let vk_slh = sk_slh.verifying_bytes();
        let mut store = UpdateStore::new(sk.verifying_key(), vk_slh, 2);
        // Too old.
        let old = sign_manifest(&sk, &sk_slh, 2, b"old", b"lock");
        assert!(store.offer(old, b"old").is_err());
        assert!(!store.needs_update());
        // Tampered binary.
        let v3 = sign_manifest(&sk, &sk_slh, 3, b"three", b"lock");
        assert!(store.offer(v3.clone(), b"tampered").is_err());
        // Good offer accepted.
        assert!(store.offer(v3, b"three").unwrap());
        assert!(store.needs_update());
        assert_eq!(store.best().unwrap().version, 3);
        // Same version re-offered: valid but not newer.
        let v3b = sign_manifest(&sk, &sk_slh, 3, b"three", b"lock");
        assert!(!store.offer(v3b, b"three").unwrap());
        // Newer wins.
        let v4 = sign_manifest(&sk, &sk_slh, 4, b"four", b"lock");
        assert!(store.offer(v4, b"four").unwrap());
        assert_eq!(store.best().unwrap().version, 4);
    }

    #[test]
    fn gossip_merge_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let sk_slh = slh::SlhReleaseKey::generate();
        let vk_slh = sk_slh.verifying_bytes();
        let mut a = UpdateStore::new(sk.verifying_key(), vk_slh.clone(), 1);
        let m = sign_manifest(&sk, &sk_slh, 2, b"bin2", b"lock");
        assert!(a.offer(m, b"bin2").unwrap());
        let msg = a.gossip_message().unwrap();
        let mut b = UpdateStore::new(sk.verifying_key(), vk_slh, 1);
        assert!(b.merge_gossip(&msg).unwrap());
        assert_eq!(
            b.best().unwrap().sha3_256_hex,
            a.best().unwrap().sha3_256_hex
        );
        // Garbage gossip rejected, state untouched.
        assert!(b.merge_gossip(b"not-json\x00bin").is_err());
        assert_eq!(b.best().unwrap().version, 2);
        assert!(b.merge_gossip(b"no-separator-here").is_err());
    }
}
