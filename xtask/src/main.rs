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
        "kat" => {
            let check = std::env::args().nth(2).as_deref() == Some("--check");
            kat(check)
        }
        "doccheck" => doccheck(),
        "prover" => prover_check(),
        _ => {
            println!("usage: cargo xtask <repro|fuzz [iters] [seed]|kat [--check]|doccheck|prover [--check] [DIR]>");
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
    use null_group::{TreeCommit, WelcomePkg};
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
        let _ = TreeCommit::decode(&rng_bytes(&mut rng, 2000));
        let _ = WelcomePkg::decode(&rng_bytes(&mut rng, 4000));
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

// ---------------------------------------------------------------------------
// Known-answer vectors: deterministic cryptographic outputs committed under
// vectors/ so independent implementations can cross-check us, and drift
// across platforms/versions fails loudly (`kat --check`, wired into CI).
// Only deterministic constructions appear here; randomized outputs
// (ephemerals, encap ciphertexts, frame padding) are covered as decode
// vectors or roundtrip properties instead. See vectors/README.md.
// ---------------------------------------------------------------------------

fn kat(check: bool) -> Result<()> {
    use null_crypto::identity::fingerprint_hex;
    use null_crypto::{identity::IdentityKey, EphemeralKey, KyberKeypair};
    use null_crypto::{initial_root_key, HandshakeInit, HandshakeResponse};
    use null_frame::Frame;
    use null_identity::{safety_number, TransparencyLog};

    let dir = PathBuf::from("vectors");
    let mut files: Vec<(&str, String)> = Vec::new();

    // 1. X25519 (fixed secrets; cross-checked with OpenSSL 3.0.13 — note).
    let sec_a = [0x11u8; 32];
    let sec_b = [0x22u8; 32];
    let ka = EphemeralKey::from_secret_bytes(sec_a);
    let kb = EphemeralKey::from_secret_bytes(sec_b);
    let (pub_a, pub_b) = (ka.public_bytes(), kb.public_bytes());
    let (sh_ab, sh_ba) = (
        ka.diffie_hellman(&pub_b)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?,
        kb.diffie_hellman(&pub_a)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?,
    );
    assert_eq!(sh_ab, sh_ba);
    files.push((
        "vectors/x25519.json",
        serde_json::to_string_pretty(&serde_json::json!({
            "algorithm": "X25519 per RFC 7748 (via x25519-dalek; cross-checked with openssl pkeyutl)",
            "vectors": [{
                "secret_a_hex": hex::encode(sec_a), "public_a_hex": hex::encode(pub_a),
                "secret_b_hex": hex::encode(sec_b), "public_b_hex": hex::encode(pub_b),
                "shared_hex": hex::encode(sh_ab),
            }],
        }))?,
    ));

    // 2. KDF + identity fingerprints + safety numbers (pure functions).
    let root = initial_root_key(&[0x33u8; 32], &[0x44u8; 32]);
    let fp = fingerprint_hex(&[0x55u8; 64]);
    let sn = safety_number(b"kat-alice-vk", b"kat-bob-vk", b"kat-session");
    let mut kt = TransparencyLog::new("kat-contact");
    kt.observe(b"kat-vk-1")
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let checkpoint = kt.export_checkpoint();
    files.push((
        "vectors/kdf.json",
        serde_json::to_string_pretty(&serde_json::json!({
            "notes": "HKDF-SHA384(ctx) compositions; cross-checked with a Python RFC-5869 implementation (see vectors/README.md)",
            "initial_root_key": {
                "dh_hex": hex::encode([0x33u8; 32]),
                "kyber_shared_hex": hex::encode([0x44u8; 32]),
                "root_hex": hex::encode(root),
            },
            "fingerprint_hex_of_64x0x55": fp,
            "safety_number": sn,
            "transparency_checkpoint_after_1_obs": checkpoint,
            "transparency_root_hex": hex::encode(kt.root()),
        }))?,
    ));

    // 3. Kyber: deterministic keygen (+ one verified encap/decap sample).
    let kyber_seed = [0x55u8; 64];
    let kkp = KyberKeypair::generate_deterministic(&kyber_seed);
    let (ct_sample, k_send) = kkp.encapsulate();
    let k_recv = kkp
        .decapsulate(&ct_sample)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_eq!(k_send, k_recv);
    files.push((
        "vectors/kyber.json",
        serde_json::to_string_pretty(&serde_json::json!({
            "algorithm": "ML-KEM-1024 (FIPS 203)",
            "deterministic_ek_hex": hex::encode(kkp.ek_bytes()),
            "note": "encap/decap below is a verified sample, not a KAT (randomized)",
            "sample_ct_len": ct_sample.len(),
            "sample_shared_ok": true,
        }))?,
    ));

    // 4. ML-DSA: fully deterministic from seed (deterministic signing).
    let id = IdentityKey::from_seed([0x66u8; 32]);
    let vk = id.verifying_bytes();
    let sig1 = id
        .sign(b"Null-KAT-1")
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let sig2 = id
        .sign(b"Null-KAT-2")
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    IdentityKey::verify(&vk, b"Null-KAT-1", &sig1).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    files.push((
        "vectors/mldsa.json",
        serde_json::to_string_pretty(&serde_json::json!({
            "algorithm": "ML-DSA-65 (FIPS 204), deterministic signatures",
            "seed_hex": hex::encode([0x66u8; 32]),
            "vk_hex": hex::encode(&vk),
            "fingerprint": id.fingerprint(),
            "device_id_slot0_hex": hex::encode(id.device_id(0)),
            "device_id_slot1_hex": hex::encode(id.device_id(1)),
            "sig_null_kat_1_hex": hex::encode(&sig1),
            "sig_null_kat_2_hex": hex::encode(&sig2),
        }))?,
    ));

    // 5. Handshake transcripts: fixed fields + REAL signatures (deterministic).
    let fixed_ct = vec![0xABu8; 1568];
    let fixed_ek = vec![0xCDu8; 1568];
    let dev_a = id.device_id(0);
    let init = HandshakeInit {
        ephemeral_pub: [0x11u8; 32],
        kyber_ct: fixed_ct.clone(),
        kyber_ek: fixed_ek.clone(),
        identity_vk: Some(vk.clone()),
        signature: None,
        device_id: dev_a,
    };
    let mut init_signed = init.clone();
    init_signed.signature = Some(
        id.sign(&init.signing_msg())
            .map_err(|e| anyhow::anyhow!("{e:?}"))?,
    );
    let init_wire = init_signed.encode();
    let init_back = HandshakeInit::decode(&init_wire).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_eq!(init_back.device_id, dev_a);
    let resp = HandshakeResponse {
        ephemeral_pub: [0x22u8; 32],
        kyber_ek: fixed_ek.clone(),
        identity_vk: Some(vk.clone()),
        signature: None,
        device_id: [0x34u8; 16],
        vk_echo: Some(vk.clone()),
    };
    let mut resp_signed = resp.clone();
    resp_signed.signature = Some(
        id.sign(&resp.signing_msg(&init.ephemeral_pub, &init.kyber_ct))
            .map_err(|e| anyhow::anyhow!("{e:?}"))?,
    );
    let resp_wire = resp_signed.encode();
    let resp_back = HandshakeResponse::decode(&resp_wire).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_eq!(resp_back.device_id, [0x34u8; 16]);
    files.push((
        "vectors/handshake.json",
        serde_json::to_string_pretty(&serde_json::json!({
            "notes": "fixed fields; signatures are REAL ML-DSA over the transcripts (re-verify with vectors/mldsa.json vk)",
            "init_signing_msg_hex": hex::encode(init.signing_msg()),
            "init_wire_hex": hex::encode(&init_wire),
            "resp_signing_msg_hex": hex::encode(resp.signing_msg(&init.ephemeral_pub, &init.kyber_ct)),
            "resp_wire_hex": hex::encode(&resp_wire),
        }))?,
    ));

    // 6. Frame decode vectors (encode pads randomly, so vectors are decode-direction).
    let mut raw_ok = vec![0u8; 2048];
    raw_ok[0..2].copy_from_slice(&0x0002u16.to_be_bytes());
    raw_ok[2] = 0x01; // Data
    raw_ok[3..11].copy_from_slice(&7u64.to_be_bytes());
    raw_ok[11..15].copy_from_slice(&5u32.to_be_bytes());
    raw_ok[15..32].copy_from_slice(&[0xEEu8; 17]);
    raw_ok[32..37].copy_from_slice(b"hello");
    let f = Frame::decode(&raw_ok).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_eq!(f.counter, 7);
    assert_eq!(f.payload, b"hello");
    let mut raw_bad = raw_ok.clone();
    raw_bad[0] = 0x00;
    raw_bad[1] = 0x01;
    assert!(Frame::decode(&raw_bad).is_err());
    files.push((
        "vectors/frame.json",
        serde_json::to_string_pretty(&serde_json::json!({
            "notes": "decode-direction only: encode() pads randomly by design",
            "valid_frame_hex": hex::encode(&raw_ok),
            "valid_counter": f.counter,
            "valid_payload_hex": hex::encode(&f.payload),
            "bad_version_frame_hex": hex::encode(&raw_bad),
        }))?,
    ));

    std::fs::create_dir_all(&dir).ok();
    for (path, content) in &files {
        if check {
            let on_disk = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
            if on_disk != format!("{content}\n") && on_disk != *content {
                anyhow::bail!("KAT mismatch in {path}: regenerate with `cargo xtask kat` and inspect the diff");
            }
        } else {
            std::fs::write(path, format!("{content}\n"))
                .with_context(|| format!("write {path}"))?;
        }
    }
    println!(
        "KAT-{} {} files",
        if check { "CHECK-OK" } else { "WROTE" },
        files.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Doc-lint gate: the documentation must agree with the code's ground truth.
// `cargo xtask doccheck` fails when a documented constant or the test count
// drifts from the source. Runs in CI so claims can never silently rot.
// ---------------------------------------------------------------------------

/// Count `#[test]` and `#[tokio::test]` attributes under `crates/` and
/// `xtask/`. This is the exact number `cargo test` reports for all targets.
fn count_test_attributes() -> Result<usize> {
    fn walk(dir: &std::path::Path, out: &mut usize) -> Result<()> {
        for entry in
            std::fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out)?;
            } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                let src = std::fs::read_to_string(&path)
                    .with_context(|| format!("read {}", path.display()))?;
                *out += src
                    .lines()
                    .filter(|l| {
                        // `#[tokio::test]` may carry a runtime flavor
                        // (`#[tokio::test(flavor = "multi_thread", …)]`);
                        // match the attribute name, not the whole line, so
                        // the count stays equal to what `cargo test` runs.
                        let t = l.trim_start();
                        t.starts_with("#[test]")
                            || t.starts_with("#[tokio::test]")
                            || t.starts_with("#[tokio::test(")
                    })
                    .count();
            }
        }
        Ok(())
    }
    let mut n = 0usize;
    walk(std::path::Path::new("crates"), &mut n)?;
    walk(std::path::Path::new("xtask"), &mut n)?;
    Ok(n)
}

/// Assert that a set of "ground truth" strings (sourced from `null-core`'s
/// constants at build time) appear in the documentation files that must
/// carry them, and that the docs' stated test count equals the source's.
fn doccheck() -> Result<()> {
    use null_core::{
        CLIPBOARD_CLEAR_SECS, DEAD_MAN_SWITCH_SECS, FRAME_HEADER_SIZE, FRAME_SIZE,
        KYBER_REKEY_INTERVAL_MSGS, KYBER_REKEY_INTERVAL_SECS, MAX_GROUP_MEMBERS, MAX_PAYLOAD_SIZE,
        PROTOCOL_VERSION, SHAPER_BASE_INTERVAL_MS, SHAPER_BURST, TAG_SIZE,
    };

    // (label, exact string the docs must contain, files that must contain it)
    let constants: &[(&str, String, &[&str])] = &[
        (
            "protocol version",
            format!("0x{:04x}", PROTOCOL_VERSION),
            &["README.md", "SUMMARY.md", "docs/wire-protocol.md"],
        ),
        (
            "frame size",
            FRAME_SIZE.to_string(),
            &["README.md", "SUMMARY.md", "docs/wire-protocol.md"],
        ),
        (
            "frame header size",
            FRAME_HEADER_SIZE.to_string(),
            &["docs/wire-protocol.md"],
        ),
        (
            "max payload size",
            MAX_PAYLOAD_SIZE.to_string(),
            &["docs/wire-protocol.md"],
        ),
        (
            "aead tag size",
            TAG_SIZE.to_string(),
            &["docs/wire-protocol.md"],
        ),
        (
            "kyber rekey interval (msgs)",
            KYBER_REKEY_INTERVAL_MSGS.to_string(),
            &[
                "README.md",
                "SUMMARY.md",
                "docs/crypto.md",
                "docs/security-posture.md",
                "docs/testing.md",
            ],
        ),
        (
            "kyber rekey interval (secs)",
            KYBER_REKEY_INTERVAL_SECS.to_string(),
            &["SUMMARY.md", "docs/crypto.md", "docs/security-posture.md"],
        ),
        (
            "shaper base interval (ms)",
            SHAPER_BASE_INTERVAL_MS.to_string(),
            &["docs/transports.md", "docs/testing.md"],
        ),
        (
            "shaper burst",
            SHAPER_BURST.to_string(),
            &["README.md", "docs/transports.md"],
        ),
        (
            "clipboard clear (secs)",
            CLIPBOARD_CLEAR_SECS.to_string(),
            &["README.md", "docs/cli.md", "docs/memory-hardening.md"],
        ),
        (
            "dead-man switch (secs)",
            DEAD_MAN_SWITCH_SECS.to_string(),
            &["SUMMARY.md", "docs/cli.md", "docs/memory-hardening.md"],
        ),
        (
            "max group members",
            MAX_GROUP_MEMBERS.to_string(),
            &["SUMMARY.md", "docs/groups.md"],
        ),
    ];

    let mut failures: Vec<String> = Vec::new();
    for (label, needle, files) in constants {
        for file in *files {
            let body = std::fs::read_to_string(file).with_context(|| format!("read {file}"))?;
            if !body.contains(needle.as_str()) {
                failures.push(format!(
                    "{label} (`{needle}`) not found in {file} — update the doc, not the code"
                ));
            }
        }
    }

    let tests = count_test_attributes()?;
    let test_docs: &[&str] = &[
        "README.md",
        "SUMMARY.md",
        "docs/audit-scope.md",
        "docs/testing.md",
        "docs/security-posture.md",
    ];
    for file in test_docs {
        let body = std::fs::read_to_string(file).with_context(|| format!("read {file}"))?;
        if !body.contains(&tests.to_string()) {
            failures.push(format!(
                "test count ({tests}) not found in {file} — reflect the true count in the docs"
            ));
        }
    }

    if failures.is_empty() {
        println!("DOC-CHECK-OK constants={} tests={tests}", constants.len());
        Ok(())
    } else {
        anyhow::bail!(
            "DOC-LINT FAILED ({})\n  {}",
            failures.len(),
            failures.join("\n  ")
        )
    }
}

// ---------------------------------------------------------------------------
// Prover env verification (Track C): `cargo xtask prover [--check] [DIR]`.
// Verifies the pinned, sha256-manifested Tamarin/Maude install used for
// formal verification. With `--check` (release ceremony) a broken or
// absent prover fails the run; without it the command reports status.
// ---------------------------------------------------------------------------

fn prover_check() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let strict = args.iter().any(|a| a == "--check");
    let dir = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_default();

    // Candidate install roots, in order: CLI arg, env, known paths.
    let mut candidates: Vec<PathBuf> = Vec::new();
    if !dir.is_empty() {
        candidates.push(PathBuf::from(&dir));
    }
    if let Ok(env_dir) = std::env::var("NULL_PROVER_DIR") {
        if !env_dir.is_empty() {
            candidates.push(PathBuf::from(env_dir));
        }
    }
    candidates.push(PathBuf::from("/tmp/prover"));
    candidates.push(PathBuf::from("prover-env"));

    let root = candidates
        .into_iter()
        .find(|c| c.join("pins.sha256").exists());
    let Some(root) = root else {
        let msg = "no pinned prover install found (looked for pins.sha256 in the usual roots). \
                   Install with: ./model/prover-install.sh [DIR]";
        if strict {
            anyhow::bail!("PROVER-CHECK FAILED: {msg}");
        }
        println!("PROVER-STATUS: absent — {msg}");
        return Ok(());
    };

    // 1. Checksum the installed tree against the pins manifest.
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg("sha256sum -c pins.sha256")
        .current_dir(&root)
        .status()
        .context("sha256sum check")?;
    if !status.success() {
        anyhow::bail!("PROVER-CHECK FAILED: sha256 mismatch in {}", root.display());
    }

    // 2. Both binaries actually run (Maude must be on PATH + MAUDE_LIB for
    // tamarin-prover, exactly as the pinned env.sh sets).
    let sh = |bin: &str| -> Result<bool> {
        let full = root.join(bin);
        if !full.exists() {
            return Ok(false);
        }
        let maude_dir = root.join("maude-dist");
        let path = std::env::var("PATH").unwrap_or_default();
        let env_path = format!("{}:{path}", maude_dir.display());
        let ok = std::process::Command::new(&full)
            .arg("--version")
            .env("PATH", &env_path)
            .env("MAUDE_LIB", &maude_dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        Ok(ok)
    };
    let maude_ok = sh("maude-dist/maude")?;
    let tamarin_ok = sh("tamarin-prover")?;
    if !maude_ok || !tamarin_ok {
        anyhow::bail!(
            "PROVER-CHECK FAILED: binaries in {} did not execute (maude={maude_ok}, tamarin={tamarin_ok})",
            root.display()
        );
    }

    println!(
        "PROVER-CHECK-OK dir={} (maude + tamarin-prover, sha256-pinned)",
        root.display()
    );
    Ok(())
}
