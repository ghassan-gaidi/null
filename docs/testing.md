# Testing matrix

How every claimed property is exercised, and by which gate. The full gate
set is in `docs/development.md`; this is the *matrix*: property → test →
failure mode.

## 1. The layers, bottom to top

| Layer | Unit area | Where |
|---|---|---|
| Crypto primitives | X25519 rejection, Kyber roundtrips, HKDF chains, identity, key lengths | `null-crypto` (14 tests) |
| Frames | 2048B codec, padding, version/type rejection, shaper, blob batching | `null-frame` (7 tests) |
| Core types | constants, `FrameType`, `TransportKind`, `ConnectionString` | `null-core` (3 tests) |
| Identity | safety number, QR, transparency, DeviceSet | `null-identity` (7 tests) |
| Session | pack/unpack, rekey-at-50, resync, Inbox recovery, goodbye, blob batching | `null-session` (8 in-crate + 5 integration files) |
| TUI | key routing, lock/unlock, duress, copy-clear | `null-tui` |
| Group | TreeKEM commits, welcomes, removal, forks | `null-group` |
| Update | hybrid sigs, downgrade floor, gossip | `null-update` |
| Transport | multiplexer, obfs4, loopback, blob batching cap | `null-transport` (11 tests) |
| CLI | two-process chats, pty TUI sessions | `null-cli` |

**110** test attributes workspace-wide (`#[test]` + `#[tokio::test]`,
including the `#[test]` inside the `ratchet_interleave.rs` `proptest!`
block), enforced by `cargo xtask doccheck`: if the docs ever stop
matching the source count, CI fails. The proptest itself runs 128
randomized flows per execution.

## 2. Cryptographic properties → evidence

| Property | Evidence | Gate |
|---|---|---|
| Establishment secrecy (no KEM leak) | Tamarin `root_secrecy` | tamarin.yml |
| Initiator KCI resistance | Tamarin `kci_initiator` | tamarin.yml |
| PINNED mutual agreement | Tamarin `mutual_agreement` + `vk_echo`/stale-ek/pinning unit tests | tamarin.yml + cargo test |
| Deniable-by-default (no signature bytes) | `deniability.rs` frame tripwire ("ML-DSA-65 vk (1952B) + signature (3309B) = 5261B minimum delta") | cargo test |
| Ratchet roundtrip + out-of-order | encrypt/decrypt interleavings, skipped-key cache (window `MAX_SKIP = 200`) | cargo test |
| Rekey trigger | `rekey_trigger_at_50` in crypto; session test `rekey_fires_at_50_and_heals_over_frames` — message 51 carries KyberRekey + Data | cargo test |
| Interleaved ratchet (stateful fuzz) | `ratchet_interleave.rs` proptest: 128 randomized alternating A↔B flows through handshake + frames + rekey boundary, asserting lossless ordered exact-match delivery and counter discipline both ways | cargo test |
| Rekey interval | constants `KYBER_REKEY_INTERVAL_MSGS = 50`, `KYBER_REKEY_INTERVAL_SECS = 604800`; doc-lint pins docs to code | doccheck |
| Lossless rekey recovery | Inbox: `MissedRekey` buffer (cap `MAX_PENDING = 16`), replay within `RETAINED_REKEYS = 8`, hard fail after `MAX_REKEY_ROUNDS = 3` "re-handshake required" | cargo test |
| No silent downgrade | `downgrade.rs` 10-case matrix (stripped init/sig/vk, version rollback, handshake-as-data, replay, rekey-as-data, control sanity) | cargo test |
| Deterministic primitives | `vectors/*.json` byte-for-byte (`cargo xtask kat --check`) | ci.yml |
| Decoder robustness | `cargo xtask fuzz` — 20k iters, every wire decoder garbage-in-no-panic, valid-encode roundtrips + 3 single-bit flips every 7th iteration | ci.yml |

## 3. Protocol layer → evidence

| Behavior | Evidence |
|---|---|
| Handshake fragmentation (2 frames, `HS_FRAG_MAX = 1900`) | codec + reassembler tests; rejects interleaving/unknown tags |
| TCP end-to-end (deniable + verified, safety-number agreement on both sides) | `e2e_tcp.rs` |
| Live two-process chats + pty-driven TUI (loopback and live listener) | `null-cli` tests |
| Goodbye + drain (no RST loss) | quit-path tests: goodbye frame first, ~2 s inbound drain |
| Traffic shaping | `TrafficShaper`: capacity `5` burst, refill 0.5/s (`SHAPER_BASE_INTERVAL_MS = 2000`), uniform 1–3 s clamped 0.5–4 s; dummy frames at shaped rate during idle | cargo test |
| Fan-out blob batching | `encode_batch`/`decode_batch` round-trip + alignment rejection; `receive_batch_aggregates_multi_frame_blob_in_order` (Data+KyberRekey+Data in one blob, order preserved); `send_frames_splits_at_blob_cap` (9000 frames → 2 blobs, 8192-frame cap, frame-aligned) | cargo test |

## 4. Groups → evidence

| Property | Evidence |
|---|---|
| O(log n) commits | `commit_cost_is_sublinear`: 8 members, depth 3, ≤ 3 bundles |
| Fork/gap/replay rejection | tampered `prev_hash` fails "does not chain"; stale epoch refused |
| Removal heals (PCS) | blanks + resolution routing; removed member defunct + state zeroized |
| Welcome/join | sealed welcome opens exactly `52 + npath*68` bytes, tree rebuilt, own-path blank until first update |
| Malicious commit DoS | `commit_with_absurd_depth_rejected`: depth > 20 refused at decode (50k member cap needs depth 16; 20 is headroom) |
| Multi-committer convergence + newcomer at latest epoch | round-robin commit test |

## 5. Endpoint → evidence

- Memory: wipe path tests, `ZeroizeOnDrop` containers, `mlock`/advisory
  hooks (unsafe blocks documented per-site).
- Clipboard: clear-after-`5`s schedule, `wl-copy` zombie reaping fixes.
- USBGuard: new `/dev` node → panic wipe + exit 0.
- TUI: key routing, PIN `1234`/duress `0000`, decoy surface, auto-lock.
- Secure input: evdev keymap tests; root-fallback warnings.

## 6. Build integrity → evidence

| Claim | Evidence |
|---|---|
| Reproducible build | `cargo run -p xtask -- repro`: two isolated `CARGO_TARGET_DIR` builds (`SOURCE_DATE_EPOCH=0`, `TZ=UTC`, `LC_ALL=C`), SHA256 must match |
| Lockfile discipline | `--locked` everywhere; `cargo_lock_digest_hex` in signed manifests |
| Docs ↔ code | `cargo run -p xtask -- doccheck` |

## 7. What is NOT yet a test (honest inventory)

- **Ratchet phase formal proofs**: stated in `model/ratchet.spthy`,
  automated proving of the chain-update loop in progress. Today: tests +
  KATs + fuzz, per `model/README.md`.
- **miri** (unsafe blocks), **sanitizer fuzzing** (cargo-fuzz), **dudect**
  (constant-time) — nightly-only harnesses, roadmap.
- **Wycheproof-style cross-check** of ML-KEM/ML-DSA against a second
  implementation (future work, noted in `vectors/README.md`).
- **Tor/I2P/Nym interop tests against real daemons** — CI has no daemons;
  live dialing is covered by local stub servers + the pty suites. Running
  `NULL_LIVE_TRANSPORT=1` against real sidecars is an operator action
  (`docs/operations.md`).

## 8. CI topology

- `ci.yml`: fmt → build → test → clippy `-D warnings` → fuzz 20000 → kat
  `--check` → doccheck, on every push/PR.
- `supply-chain.yml`: cargo-audit (RustSec) weekly + on manifest/lock
  changes, and cargo-deny `bans`/`licenses`/`sources` fail-closed gates
  (see `deny.toml`).
- `tamarin.yml`: on `model/**` changes only — Maude 3.5.1 + prover 1.12.0
  (both sha256-pinned), proves `handshake.spthy` 5/5, parse-checks
  `ratchet.spthy`/`ntr.spthy`. Separate job so prover flakiness can never
  mask a code regression (and vice versa).