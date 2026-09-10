//! Optional identity layer (§4.3): ML-DSA-65 fingerprints, safety
//! numbers, QR verification. Default mode is deniable (no signatures).

use null_core::{NullError, Result};
use sha3::{Digest, Sha3_256};

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

/// Parse `ml-dsa:<HEX>` fingerprint param from connection string.
pub fn parse_identity_fingerprint(s: &str) -> Result<Vec<u8>> {
    let hexpart = s.strip_prefix("ml-dsa:").ok_or_else(|| {
        NullError::Identity(format!("identity must start with ml-dsa:, got `{s}`"))
    })?;
    hex::decode_fallback(hexpart)
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

mod hex {
    use super::*;
    pub fn decode_fallback(h: &str) -> Result<Vec<u8>> {
        let h = h.trim();
        if !h.len().is_multiple_of(2) || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(NullError::Identity("bad hex fingerprint".into()));
        }
        (0..h.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&h[i..i + 2], 16)
                    .map_err(|e| NullError::Identity(format!("hex: {e}")))
            })
            .collect()
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
}
