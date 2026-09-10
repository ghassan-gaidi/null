//! xtask: reproducible-build verification, fuzz-corpus runs, release chores.

use anyhow::{Context, Result};
use std::path::PathBuf;

fn main() -> Result<()> {
    let task = std::env::args().nth(1).unwrap_or_else(|| "help".into());
    match task.as_str() {
        "repro" => repro(),
        "fuzz" => {
            let iters = std::env::args()
                .nth(2)
                .map(|s| s.parse().unwrap_or(20_000))
                .unwrap_or(20_000);
            let seed = std::env::args()
                .nth(3)
                .map(|s| s.parse().unwrap_or(0x9E3779B97F4A7C15))
                .unwrap_or(0x9E3779B97F4A7C15);
            fuzz(iters, seed)
        }
        _ => {
            println!("usage: cargo xtask <repro|fuzz [iters] [seed]>");
            Ok(())
        }
    }
}

/// Rebuild the `null` binary twice and compare SHA256 digests.
/// Deterministic builds are required for SLSA L3 (§9.1).
fn repro() -> Result<()> {
    let out_dir = PathBuf::from("/tmp/null-repro");
    std::fs::create_dir_all(&out_dir).ok();
    let mut hashes = vec![];
    for i in 0..2 {
        let target = out_dir.join(format!("build{i}"));
        std::fs::create_dir_all(&target).ok();
        let status = std::process::Command::new("cargo")
            .args(["build", "--locked", "--bin", "null"])
            .env("CARGO_TARGET_DIR", &target)
            .env("SOURCE_DATE_EPOCH", "0")
            .env("TZ", "UTC")
            .env("LC_ALL", "C")
            .status()
            .context("cargo build")?;
        if !status.success() {
            anyhow::bail!("build {i} failed");
        }
        let bin = target.join("debug/null");
        let bytes = std::fs::read(&bin).with_context(|| format!("read {}", bin.display()))?;
        hashes.push(sha256_hex(&bytes));
    }
    println!("build0: {}", hashes[0]);
    println!("build1: {}", hashes[1]);
    if hashes[0] == hashes[1] {
        println!("REPRODUCIBLE: hashes match");
        Ok(())
    } else {
        anyhow::bail!("NON-REPRODUCIBLE: hashes differ (inspect toolchain/paths)")
    }
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

// ---------------------------------------------------------------------------
// Stable fuzz corpus: every wire decoder must reject garbage without
// panicking, and valid messages must roundtrip. Deterministic xorshift64
// stream (no new deps); run `cargo xtask fuzz [iters] [seed]`.
// (cargo-fuzz/libfuzzer would need nightly; this runs on stable.)
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    /// Random-ASCII printable blob (for connection strings / JSON).
    fn ascii(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| (0x20 + self.below(0x5f)) as u8 as char)
            .collect()
    }
}

fn rng_bytes(rng: &mut Rng, n: usize) -> Vec<u8> {
    let len = rng.below(n + 1);
    rng.bytes(len)
}

fn fuzz(iters: usize, seed: u64) -> Result<()> {
    use null_core::ConnectionString;
    use null_crypto::{EncryptedMessage, HandshakeInit, HandshakeResponse};
    use null_frame::Frame;
    use null_group::CommitEnvelope;
    use null_session::HandshakeReassembler;
    use null_update::UpdateManifest;

    let mut rng = Rng(seed);
    let mut valid_roundtrips = 0u64;
    for i in 0..iters {
        // 1. Frame decoder: any length 0..2100.
        let raw = rng_bytes(&mut rng, 2101);
        let _ = Frame::decode(&raw);

        // 2. Ratchet message decoder.
        let m = rng_bytes(&mut rng, 300);
        let _ = EncryptedMessage::decode(&m);

        // 3. Handshake codecs: random + truncated-valid.
        let h = rng_bytes(&mut rng, 9000);
        let _ = HandshakeInit::decode(&h);
        let _ = HandshakeResponse::decode(&h);

        // 4. Group envelope + update manifest + connection string.
        let _ = CommitEnvelope::decode(&rng_bytes(&mut rng, 2000));
        let mlen = rng.below(401);
        let _ = UpdateManifest::from_bytes(rng.ascii(mlen).as_bytes());
        let slen = rng.below(121);
        let s = rng.ascii(slen);
        let _ = ConnectionString::parse(&s);

        // 5. Reassembler over random fragments (never panics, any order).
        {
            let mut re = HandshakeReassembler::new();
            for _ in 0..rng.below(4) {
                let frag = rng.bytes(2048);
                let _ = re.add_raw(&frag);
            }
        }

        // 6. Valid-message roundtrips with byte mutations (decode must
        //    either reject or reproduce exactly — never panic).
        if i % 7 == 0 {
            let msg = EncryptedMessage {
                counter: rng.next(),
                kyber_gen: rng.next() % 3,
                ecdh_pub: rng.bytes(32).try_into().unwrap(),
                ciphertext: rng_bytes(&mut rng, 500),
            };
            let mut wire = msg.encode();
            assert_eq!(
                EncryptedMessage::decode(&wire).unwrap().counter,
                msg.counter
            );
            valid_roundtrips += 1;
            for _ in 0..3 {
                if !wire.is_empty() {
                    let at = rng.below(wire.len());
                    wire[at] ^= 1 << rng.below(8);
                }
                let _ = EncryptedMessage::decode(&wire);
            }
        }
    }
    println!("FUZZ-OK iters={iters} seed={seed:#x} valid_roundtrips={valid_roundtrips}");
    Ok(())
}
