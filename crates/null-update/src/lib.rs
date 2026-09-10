//! Anonymous update distribution (§9.3): signed manifest fetched over
//! onion / P2P gossip. Hybrid Ed25519 (+ SPHINCS+ slot reserved).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use null_core::{NullError, Result};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Update manifest (§9.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateManifest {
    pub version: u64,
    pub sha3_256_hex: String,
    /// Ed25519 signature over (version ‖ sha3_hex).
    pub ed25519_sig_hex: String,
    /// Reserved SPHINCS+-SHA2-128s signature slot (hex, may be empty until
    /// PQ signing lands; verification skips empty slot).
    #[serde(default)]
    pub sphincs_sig_hex: String,
    pub cargo_lock_digest_hex: String,
}

impl UpdateManifest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!("{}:{}", self.version, self.sha3_256_hex).into_bytes()
    }

    pub fn verify(&self, vk: &VerifyingKey, min_version: u64) -> Result<()> {
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
        // SPHINCS+ slot: if present, length-check (full PQ verify = future).
        if !self.sphincs_sig_hex.is_empty() && self.sphincs_sig_hex.len() < 16 {
            return Err(NullError::Update("sphincs slot malformed".into()));
        }
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
    current_version: u64,
    best: Option<(UpdateManifest, Vec<u8>)>,
}

impl UpdateStore {
    pub fn new(release_key: VerifyingKey, current_version: u64) -> Self {
        Self {
            release_key,
            current_version,
            best: None,
        }
    }

    /// Validate a manifest+binary pair from ANY source (onion fetch or peer
    /// gossip). Returns true iff it becomes the new best offer.
    pub fn offer(&mut self, manifest: UpdateManifest, binary: &[u8]) -> Result<bool> {
        manifest.verify(&self.release_key, self.current_version + 1)?;
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
        let m = sign_manifest(&sk, 3, b"binary-bytes", b"lock");
        m.verify(&sk.verifying_key(), 3).unwrap();
        assert!(m.verify(&sk.verifying_key(), 4).is_err());
        let other = SigningKey::generate(&mut OsRng);
        assert!(m.verify(&other.verifying_key(), 1).is_err());
    }

    #[test]
    fn store_accepts_newer_rejects_rest() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut store = UpdateStore::new(sk.verifying_key(), 2);
        // Too old.
        let old = sign_manifest(&sk, 2, b"old", b"lock");
        assert!(store.offer(old, b"old").is_err());
        assert!(!store.needs_update());
        // Tampered binary.
        let v3 = sign_manifest(&sk, 3, b"three", b"lock");
        assert!(store.offer(v3.clone(), b"tampered").is_err());
        // Good offer accepted.
        assert!(store.offer(v3, b"three").unwrap());
        assert!(store.needs_update());
        assert_eq!(store.best().unwrap().version, 3);
        // Same version re-offered: valid but not newer.
        let v3b = sign_manifest(&sk, 3, b"three", b"lock");
        assert!(!store.offer(v3b, b"three").unwrap());
        // Newer wins.
        let v4 = sign_manifest(&sk, 4, b"four", b"lock");
        assert!(store.offer(v4, b"four").unwrap());
        assert_eq!(store.best().unwrap().version, 4);
    }

    #[test]
    fn gossip_merge_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut a = UpdateStore::new(sk.verifying_key(), 1);
        let m = sign_manifest(&sk, 2, b"bin2", b"lock");
        assert!(a.offer(m, b"bin2").unwrap());
        let msg = a.gossip_message().unwrap();
        let mut b = UpdateStore::new(sk.verifying_key(), 1);
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
