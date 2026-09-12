//! Optional identity layer (§4.3): ML-DSA-65 fingerprints, safety
//! numbers, QR verification. Default mode is deniable (no signatures).

use null_core::{NullError, Result};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// `SHA3-256(IK_A ‖ IK_B ‖ session_id)` → 12 groups of 5 digits.
/// Inputs are ordered canonically so both peers display the same number
/// regardless of who initiated.
pub fn safety_number(ik_a: &[u8], ik_b: &[u8], session_id: &[u8]) -> String {
    let (first, second) = if ik_a <= ik_b {
        (ik_a, ik_b)
    } else {
        (ik_b, ik_a)
    };
    let mut h = Sha3_256::new();
    h.update(first);
    h.update(second);
    h.update(session_id);
    let digest = h.finalize();
    // Map 30 bytes → 12 groups of 5-digit numbers (0..99999).
    let mut groups = Vec::new();
    for i in 0..12 {
        let b0 = digest[(i * 2) % 32] as u32;
        let b1 = digest[(i * 2 + 1) % 32] as u32;
        let b2 = digest[(i * 3) % 32] as u32;
        let n = (b0 << 16 | b1 << 8 | b2) % 100_000;
        groups.push(format!("{n:05}"));
    }
    groups.join(" ")
}

/// Render safety number as ASCII QR (for TUI in-person verification).
/// Uses the `qrcode` crate to produce block-art.
pub fn safety_number_qr_ascii(safety_number: &str) -> Result<String> {
    use qrcode::QrCode;
    let code = QrCode::new(safety_number.as_bytes())
        .map_err(|e| NullError::Identity(format!("qr: {e}")))?;
    Ok(code
        .render::<char>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build())
}

/// Group member id for one device: `SHA3-256("Null-v2.0-device-member:" ‖
/// identity_fp ‖ device_id)`. Deterministic per (identity, device), so all
/// peers derive the same member id for a device without extra exchange, and
/// revoking the device is exactly `Group::remove(device_member_id(...))`.
pub fn device_member_id(identity_fp: &str, device_id: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"Null-v2.0-device-member:");
    h.update(identity_fp.as_bytes());
    h.update(device_id);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Multi-device sets (docs/multidevice.md).
//
// One identity (ML-DSA key), N device sub-keys (Kyber + X25519 each). Each
// device holds its own ratchet sessions; revocation is group removal of the
// device's member id. In-RAM only, like everything else here.
// ---------------------------------------------------------------------------

/// One enrolled device: its long-term Kyber ek for session establishment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub kyber_ek: Vec<u8>,
    pub revoked: bool,
    /// Monotonic enrollment counter (ordering, not wall-clock).
    pub added_epoch: u64,
}

/// The set of devices sharing one identity fingerprint.
#[derive(Debug, Clone)]
pub struct DeviceSet {
    identity_fp: String,
    devices: HashMap<[u8; 16], DeviceInfo>,
    next_epoch: u64,
}

impl DeviceSet {
    pub fn new(identity_fp: impl Into<String>) -> Self {
        Self {
            identity_fp: identity_fp.into(),
            devices: HashMap::new(),
            next_epoch: 0,
        }
    }

    pub fn identity_fp(&self) -> &str {
        &self.identity_fp
    }

    /// Enroll a device key, returning its stable id. Re-enrolling the same
    /// key material is idempotent only if the caller reuses the id — a fresh
    /// random id always creates a distinct device entry.
    pub fn add_device(&mut self, device_id: [u8; 16], kyber_ek: Vec<u8>) -> Result<()> {
        if kyber_ek.is_empty() {
            return Err(NullError::Identity("empty device kyber ek".into()));
        }
        if self.devices.contains_key(&device_id) {
            return Err(NullError::Identity("device id already enrolled".into()));
        }
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        self.devices.insert(
            device_id,
            DeviceInfo {
                kyber_ek,
                revoked: false,
                added_epoch: epoch,
            },
        );
        Ok(())
    }

    /// Revoke a device. Unknown or already-revoked ids fail (loud, not silent).
    pub fn revoke(&mut self, device_id: &[u8; 16]) -> Result<()> {
        match self.devices.get_mut(device_id) {
            None => Err(NullError::Identity("unknown device id".into())),
            Some(info) if info.revoked => Err(NullError::Identity("device already revoked".into())),
            Some(info) => {
                info.revoked = true;
                Ok(())
            }
        }
    }

    pub fn is_revoked(&self, device_id: &[u8; 16]) -> bool {
        self.devices
            .get(device_id)
            .map(|d| d.revoked)
            .unwrap_or(true)
    }

    /// `(device_id, kyber_ek)` for every non-revoked device: the fan-out set.
    pub fn active_devices(&self) -> Vec<([u8; 16], Vec<u8>)> {
        let mut out: Vec<_> = self
            .devices
            .iter()
            .filter(|(_, d)| !d.revoked)
            .map(|(id, d)| (*id, d.kyber_ek.clone()))
            .collect();
        out.sort_unstable_by_key(|(id, _)| *id);
        out
    }

    /// Group member id for one of our devices (for `Group::add`/`remove`).
    pub fn member_id(&self, device_id: &[u8; 16]) -> [u8; 32] {
        device_member_id(&self.identity_fp, device_id)
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn active_count(&self) -> usize {
        self.devices.values().filter(|d| !d.revoked).count()
    }
}

// ---------------------------------------------------------------------------
// Key transparency (§4.3, Contact-Key-Verification analogue).
//
// In-RAM append-only Merkle log of every peer identity key observed for a
// contact. First sighting records (TOFU); any later change FAILS CLOSED —
// the session aborts instead of continuing under a possibly-substituted
// key. Checkpoints export as plain text for out-of-band comparison.
// Deliberately memory-only: Null never writes identity state to disk.
// ---------------------------------------------------------------------------

/// One observed identity key binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparencyLeaf {
    /// 0-based observation index (monotonic per contact).
    pub epoch: u64,
    /// `SHA3-256` of the raw verification-key bytes.
    pub vk_hash: [u8; 32],
}

fn vk_hash(vk_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"Null-v2.0-transparency-vk:");
    h.update(vk_bytes);
    h.finalize().into()
}

fn leaf_hash(leaf: &TransparencyLeaf) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"Null-v2.0-transparency-leaf:");
    h.update(leaf.epoch.to_be_bytes());
    h.update(leaf.vk_hash);
    h.finalize().into()
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// In-RAM transparency log for one contact (labelled by onion host or fingerprint).
#[derive(Debug, Clone)]
pub struct TransparencyLog {
    contact: String,
    leaves: Vec<TransparencyLeaf>,
}

impl TransparencyLog {
    pub fn new(contact: impl Into<String>) -> Self {
        Self {
            contact: contact.into(),
            leaves: Vec::new(),
        }
    }

    pub fn contact(&self) -> &str {
        &self.contact
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Observe the peer's current verification key. First sighting records
    /// it; any later sighting with different bytes fails closed.
    pub fn observe(&mut self, vk_bytes: &[u8]) -> Result<()> {
        let hash = vk_hash(vk_bytes);
        match self.leaves.last() {
            None => {
                self.leaves.push(TransparencyLeaf {
                    epoch: 0,
                    vk_hash: hash,
                });
                Ok(())
            }
            Some(last) if last.vk_hash == hash => Ok(()),
            Some(last) => Err(NullError::Identity(format!(
                "identity key CHANGED for contact {} (epoch {} → {}, possible MITM); aborting",
                self.contact,
                last.epoch,
                self.leaves.len()
            ))),
        }
    }

    /// Merkle root over observed leaves (all-zeros when empty).
    pub fn root(&self) -> [u8; 32] {
        let mut level: Vec<[u8; 32]> = self.leaves.iter().map(leaf_hash).collect();
        if level.is_empty() {
            return [0u8; 32];
        }
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut it = level.into_iter();
            while let Some(left) = it.next() {
                let right = it.next().unwrap_or(left);
                let mut h = Sha3_256::new();
                h.update(b"Null-v2.0-transparency-node:");
                h.update(left);
                h.update(right);
                next.push(h.finalize().into());
            }
            level = next;
        }
        level[0]
    }

    /// Exportable checkpoint: `null-kt-v1:<contact>:<leaves>:<hex root>`.
    /// Compare out-of-band (voice, QR, printed card) to detect substitution.
    pub fn export_checkpoint(&self) -> String {
        format!(
            "null-kt-v1:{}:{}:{}",
            self.contact,
            self.leaves.len(),
            hex_of(&self.root())
        )
    }

    /// Verify a checkpoint obtained out-of-band against local state.
    pub fn verify_checkpoint(&self, checkpoint: &str) -> Result<()> {
        if self.export_checkpoint() == checkpoint.trim() {
            Ok(())
        } else {
            Err(NullError::Identity(format!(
                "transparency checkpoint mismatch for contact {} (possible MITM or desync)",
                self.contact
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_number_format() {
        let s = safety_number(b"A", b"B", b"sess");
        assert_eq!(s.split_whitespace().count(), 12);
        for g in s.split_whitespace() {
            assert_eq!(g.len(), 5);
        }
    }

    #[test]
    fn qr_renders() {
        let s = safety_number(b"A", b"B", b"sess");
        let qr = safety_number_qr_ascii(&s).unwrap();
        assert!(qr.contains('█') || qr.contains(' '));
    }

    #[test]
    fn transparency_first_sighting_records_repeat_ok() {
        let mut log = TransparencyLog::new("peer.onion");
        assert!(log.is_empty());
        log.observe(b"vk-bytes-1").unwrap();
        assert_eq!(log.len(), 1);
        log.observe(b"vk-bytes-1").unwrap();
        assert_eq!(log.len(), 1, "repeat sighting appends nothing");
        assert_ne!(log.root(), [0u8; 32]);
    }

    #[test]
    fn transparency_change_fails_closed() {
        let mut log = TransparencyLog::new("peer.onion");
        log.observe(b"vk-original").unwrap();
        let err = log.observe(b"vk-substituted").unwrap_err();
        assert!(format!("{err:?}").contains("CHANGED"));
        assert_eq!(log.len(), 1, "poisoned key never recorded");
    }

    #[test]
    fn transparency_checkpoint_roundtrip_and_mismatch() {
        let mut a = TransparencyLog::new("peer.onion");
        let mut b = TransparencyLog::new("peer.onion");
        a.observe(b"vk-1").unwrap();
        b.observe(b"vk-1").unwrap();
        let cp = a.export_checkpoint();
        assert!(cp.starts_with("null-kt-v1:peer.onion:1:"));
        b.verify_checkpoint(&cp).unwrap();
        b.verify_checkpoint("null-kt-v1:peer.onion:1:deadbeef")
            .unwrap_err();
        // Different contact label => different checkpoint (no cross-binding).
        let mut c = TransparencyLog::new("other.onion");
        c.observe(b"vk-1").unwrap();
        c.verify_checkpoint(&cp).unwrap_err();
    }

    #[test]
    fn transparency_root_changes_with_history() {
        let mut a = TransparencyLog::new("x");
        let mut b = TransparencyLog::new("x");
        a.observe(b"vk-1").unwrap();
        b.observe(b"vk-1").unwrap();
        assert_eq!(a.root(), b.root());
        // Same key re-observed: root stable (no new leaf).
        a.observe(b"vk-1").unwrap();
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn device_set_enroll_revoke_fanout() {
        let mut set = DeviceSet::new("ml-dsa:fp");
        assert_eq!(set.active_count(), 0);
        let d0 = [0x11u8; 16];
        let d1 = [0x22u8; 16];
        set.add_device(d0, b"ek0".to_vec()).unwrap();
        set.add_device(d1, b"ek1".to_vec()).unwrap();
        assert_eq!(set.active_count(), 2);
        // Duplicates and empty keys rejected.
        assert!(set.add_device(d0, b"ekX".to_vec()).is_err());
        assert!(set.add_device([0x33u8; 16], Vec::new()).is_err());
        // Unknown ids count as revoked (fail closed for fan-out).
        assert!(set.is_revoked(&[0x99u8; 16]));
        set.revoke(&d0).unwrap();
        assert!(set.is_revoked(&d0));
        assert!(set.revoke(&d0).is_err(), "double revoke is loud");
        assert!(set.revoke(&[0x99u8; 16]).is_err());
        let active = set.active_devices();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].0, d1);
        // Member ids are deterministic per (identity, device).
        assert_eq!(set.member_id(&d1), device_member_id("ml-dsa:fp", &d1));
        assert_ne!(
            set.member_id(&d0),
            set.member_id(&d1),
            "devices must not collide"
        );
        assert_ne!(
            DeviceSet::new("ml-dsa:other").member_id(&d1),
            set.member_id(&d1),
            "member ids are identity-bound"
        );
    }
}
