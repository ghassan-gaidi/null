# Changelog

All notable changes to Null are listed below. The format follows
[Keep a Changelog](https://keepachangelog.com/); versioning follows
[SemVer](https://semver.org/) loosely (single-binary messenger, one release line).

## [2.0.0] — 2026-09

Null v2.0: post-quantum, metadata-resistant terminal messenger with the
Null Triple Ratchet (NTR). Linux-first; RAM-only; no disk writes, no
accounts, no central server.

### Added

- **Cryptography (NTR)**
  - Handshake: X25519 + ML-KEM-1024 (Kyber-1024, FIPS 203) key
    establishment, deniable by default; opt-in `--verified` mode adds
    mutual ML-DSA-65 (FIPS 204) signatures, fingerprint pinning via the
    `i=` connection-string parameter, and a canonical 12×5-digit safety
    number plus scannable QR.
  - Ratchet: per-message X25519 ECDH (rotate-before-send), per-message
    HKDF-SHA384 symmetric chain, and periodic ML-KEM-1024 re-encapsulation
    (every 50 messages or 604800 seconds / 7 days) mixed into the root —
    Apple PQ3 Level-3-style ongoing post-quantum rekeying.
  - ChaCha20-Poly1305 message AEAD, 96-bit counter nonce, associated data
    binding sender/receiver + protocol version.
  - Out-of-order delivery via a skipped chain-key cache (window 200, wiped
    on drop); replays and oversized gaps rejected.
  - Lossless rekey recovery: every message carries its PQ generation
    counter; missed rekeys are requested and replayed within an 8-rekey
    retention window, with a hard 3-round cap before demanding a
    re-handshake.
- **Formal verification**
  - `model/handshake.spthy` proven 5/5 with tamarin-prover 1.12.0
    (Maude 3.5.1, both sha256-pinned in CI): establishment secrecy,
    initiator KCI resistance, verified-PINNED mutual agreement, honest-run
    executability. `model/ratchet.spthy` modelled line-for-line; proofs in
    progress (see `model/README.md`).
  - Committed KAT vectors in `vectors/` (X25519 cross-checked with
    OpenSSL, HKDF chains with an independent Python RFC 5869
    implementation), enforced by `cargo xtask kat --check`.
- **Transports**: Tor (SOCKS5 + control-port ephemeral onion
  provisioning), I2P (SAMv3), Nym SOCKS5, Snowflake, WebTunnel, obfs4 —
  latency-weighted election with transparent failover; length-prefixed blob
  pipes; goodbye handshake + 2s drain on quit so no peer loses in-flight
  messages to a TCP RST.
- **Traffic analysis resistance**: fixed 2048-byte frames (32-byte header,
  randomized padding), token-bucket shaping (1 frame/2s base, burst 5,
  1–3 s jitter), and indistinguishable dummy cover frames while idle.
- **Memory & endpoint hardening**: RAM-only operation, `mlock` +
  `MADV_DONTDUMP`, 3-pass panic wipe (random → zero → random) on exit,
  signal, panic, USBGuard trigger, and peer disconnect; alternate-screen
  TUI with scrollback kill; clipboard auto-clear in 5s with clipboard-
  manager warnings; evdev secure input (root); duress PIN + decoy mode;
  auto-lock and optional dead-man switch; HSM tiering (Tier-1 RAM default,
  TPM/YubiKey/Secure-Enclave presence probe).
- **Groups (Null-MLS)**: real ratchet tree with ML-KEM-1024 node keys,
  O(log n) path commits (proven: 3 bundles at depth 3 for 8 members),
  blanks on removal, epoch hash-chaining (fork/gap/replay rejection),
  Welcome packages sealed to the joiner's key, up to 50,000 members.
- **Updates**: hybrid Ed25519 + SLH-DSA-SHA2-128s release signatures (both
  mandatory), monotonic version with downgrade rejection, binary +
  `Cargo.lock` hashes, signature-checked P2P gossip (newest-verified wins).
- **Identity**: in-RAM key-transparency log (fail closed on key change,
  exportable checkpoints), device sets with `SHA3-256`-derived stable
  device ids, multi-device fan-out and revocation.
- **Tooling**: `cargo xtask` with `repro` (double-build hash comparison),
  `fuzz` (deterministic stable-channel wire-decoder corpus), `kat
  [--check]` (known-answer vectors), and `doccheck` (docs-vs-code constant
  lint).

### Changed

- Handshake hardened with unknown-key-share protection: verified mode
  requires the responder to echo the initiator's verification key
  (`vk_echo`) and to return the exact advertised Kyber key (stale-key
  fail-closed).
- `EphemeralKey::diffie_hellman` now returns `Result` and rejects the
  basepoint, non-curve points, small-order points, and all-zero outputs
  (degenerate peers found by the Tamarin `root_secrecy` model).
- `device_id` fixed to 16 bytes and bound into both verified handshake
  transcripts for multi-device safety.
- TreeKEM commit decode caps declared depth at 20 to block a
  malicious-commit DoS (50k members needs depth 16; 20 is headroom).

### Fixed

- Quitting can no longer RST away a peer's in-flight messages: `/quit` and
  EOF now send a goodbye frame and drain inbound for ~2s first.
- Clipboard clear race and `wl-copy` zombie reaping on Wayland.
- USBGuard detector no longer double-counts or self-triggers on dirs.
- Group depth cap prevents shift-overflow panics and OOM from absurd
  declared depths.
- Test-count references in docs updated to the true 91.

### Known limitations (see `README.md`, `docs/security-posture.md`)

- Ratchet phase proofs (`model/ratchet.spthy`) are in progress; behavior is
  covered by tests + KATs.
- Nightly-only harnesses (miri, cargo-fuzz with sanitizers, dudect) remain
  future work.
- TPM/YubiKey/Secure Enclave key *operations* are detection-only; native
  stacks (tpm2-tss, ykman, SE SDK) are not yet linked.
- Bridge transports (Snowflake/WebTunnel/obfs4) need operator-provided
  sidecars and fail closed without `NULL_LIVE_TRANSPORT=1`.
- Deniable mode only shields transcript *forgery*; it is not anonymity and
  not protection against a peer who screenshots or testifies.

[2.0.0]: https://github.com/ghassan-gaidi/null/releases/tag/v2.0.0