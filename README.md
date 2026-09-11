# Null — Post-Quantum, Metadata-Resistant Terminal Messenger

[![CI](https://github.com/ghassan-gaidi/null/actions/workflows/ci.yml/badge.svg)](https://github.com/ghassan-gaidi/null/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

**Null** is a zero-telemetry, serverless, post-quantum peer-to-peer terminal
messenger. It runs entirely in volatile RAM, leaves zero forensic residue, and
provides **Level 3 post-quantum messaging security**: ongoing post-quantum
rekeying inside a continuous triple ratchet, multi-transport censorship
resistance, and hardware-aware key isolation — all in a terminal-native app.

Everything below is implemented and tested in this repository: 89 tests green,
`clippy -D warnings` clean, reproducible builds verified bit-identical, and
live two-process chats (deniable, verified, TUI) proven over real sockets.

---

## Why Null

| Capability | Null | Typical E2E messengers |
|---|---|---|
| Ongoing post-quantum ratcheting (Kyber re-encap ≤ 50 msgs / 7 days) | ✅ | ❌ |
| Classical per-message ECDH ratchet + symmetric chain | ✅ | ✅-ish |
| Out-of-order tolerant decryption (skipped-key cache) | ✅ | ✅-ish |
| Deniable by default, opt-in ML-DSA-65 verified mode | ✅ | ❌ |
| In-RAM key-transparency log, fail-closed on key change | ✅ | Rare |
| Multi-device: bound transcripts, fan-out, device revocation | ✅ | ✅-ish |
| Downgrade-attack matrix enforced by test (10 cases) | ✅ | Rare |
| Multi-transport: Tor / I2P / Nym / Snowflake / WebTunnel / obfs4 | ✅ | ❌ |
| Fixed 2048-byte frames + token-bucket shaping + dummy cover | ✅ | ❌ |
| RAM-only, mlock, 3-pass panic wipe, no disk writes | ✅ | ❌ |
| Duress PIN, decoy mode, USBGuard, auto-lock, clipboard auto-clear | ✅ | ❌ |
| Group messaging with PCS-preserving commits | ✅ | ✅-ish |
| Signed, gossip-distributed, downgrade-proof updates | ✅ | ❌ |
| Reproducible builds (verified in CI-able `xtask`) | ✅ | Rare |

---

## Null vs Signal vs iMessage vs Telegram

Rough comparison against publicly documented designs, on the dimensions
Null optimizes for. Mainstream apps win on maturity, audit depth, and
usability; Null trades all of that for serverlessness and
metadata-resistance.

| Dimension | Null | Signal | iMessage | Telegram |
|---|---|---|---|---|
| Architecture | Serverless P2P over Tor / I2P / Nym; no accounts, no central server | Centralized servers; account required | Centralized (Apple); Apple ID / phone number | Centralized cloud; phone-number account |
| E2E by default | Yes — every session | Yes | Yes (but iCloud backups can expose message history unless Advanced Data Protection is on) | No — only opt-in Secret Chats are E2E; default cloud chats are server-accessible |
| Identity | `.onion` + keys; `i=` fingerprint pinned out-of-band | Phone number (usernames added as a contact layer, number still required) | Apple ID / phone number | Phone number (@usernames are aliases) |
| Post-quantum | ML-KEM-1024 at handshake **plus** ongoing rekey (≤ 50 msgs / 7 days) | PQXDH at handshake; ongoing ratchet remains classical ECDH | PQ3: PQ handshake plus ongoing PQ rekeying | None (classical MTProto) |
| Forward secrecy / healing | Per-message ECDH + one-way chain + PQ rekey; loss becomes loud failure, never silent divergence | Double Ratchet (classical FS/PCS) | PQ3 ratchet (FS + ongoing PQ healing) | Secret Chats rotate keys; cloud chats have no E2E FS story |
| Deniable mode | Default: no signatures at all; `--verified` (ML-DSA-65) is opt-in | No user-facing deniable mode | No | No |
| Metadata / cover traffic | Fixed 2048B frames, 1 frame/2s shaping + jitter, dummy cover; `.onion` resolution is remote (no local DNS leak) | Sealed sender + TLS to central servers; no padding/cover framing comparable to Null's | TLS to Apple infra; no user-visible cover traffic | TLS/MTProto to Telegram servers |
| Censorship circumvention | Tor bridges, Snowflake, WebTunnel, obfs4, pluggable transports | Built-in circumvention (TLS proxies and related techniques) | None built-in | MTProto proxies |
| Source availability | Fully open (MIT OR Apache-2.0), reproducible builds, Tamarin-checked handshake, committed KAT vectors | Open clients; server code published but run centrally | Closed source | Open clients; server closed |
| Endpoint posture | Terminal-native, RAM-only, `mlock`, 3-pass panic wipe, duress PIN / decoy mode, USBGuard, clipboard auto-clear | Standard mobile/desktop app; data at rest on device, OS backups apply | Standard app; backups and iCloud sync apply | Standard app; cloud history by design |
| Groups | TreeKEM commits, O(log n) path encapsulations, epoch hash-chaining (fork/gap/replay rejection) | Sender Keys (fan-out per sender) | Apple key-service mediated groups | Server-mediated groups |

Caveats, stated plainly:

- Signal and iMessage have far deeper external review and far larger
  adversarial exposure than Null; a comparison table is not a security
  ranking.
- Telegram's default chats are outside the E2E comparison by design —
  that is a product choice with real usability benefits (seamless
  multi-device cloud sync), not just a missing feature.
- "Post-quantum" rows describe asymmetric key establishment and
  rekeying only; symmetric primitives (ChaCha20-Poly1305, AES) are
  considered quantum-resistant at sufficient key sizes across all four.
- Null's deniability is a protocol property of the default mode
  (no signatures to show a third party), not anonymity and not
  protection against a peer that screenshots or testifies.

---

## Threat model

Null is designed to resist:

| Adversary | Defense |
|---|---|
| Passive global observer (traffic analysis, timing) | 2048B fixed frames, 1 frame/2s shaping + jitter, dummy cover traffic, Tor/I2P/Nym routing |
| Active network attacker (MitM, injection) | Triple-DH + Kyber handshake, AEAD with bound associated data, per-message ratchet |
| Quantum adversary (harvest-now-decrypt-later) | ML-KEM-1024 now + periodic re-encapsulation; ML-DSA-65 identities |
| Local forensic analyst (disk, swap, cold boot) | Zero disk writes, `mlock` + `MADV_DONTDUMP`, `PR_SET_DUMPABLE=0`, 3-pass wipe, sleep-inhibitor guidance |
| Endpoint malware (user-level) | `/dev/tty` + optional evdev secure input, clipboard auto-clear, anti-screenshot hints per OS |
| Nation-state censor (DPI, bridge blocking) | Tor bridges, Snowflake, WebTunnel, obfs4, protocol mimicry |
| Coercion / device seizure | Duress PIN (silent wipe), decoy mode, USBGuard panic wipe, dead-man auto-lock |
| Supply chain | Pinned `Cargo.lock`, reproducible builds, signed update manifests |

---

## Architecture

```
┌─ null-cli ──────────────────────────────────────────────┐
│ flags · listener/initiator · Ratatui TUI · line REPL    │
├─ null-session ──────────────────────────────────────────┤
│ handshake framing+reassembly · pack/unpack pipeline     │
├─ null-crypto ───────────────┬─ null-frame ──────────────┤
│ NTR triple ratchet          │ 2048B frames · shaper     │
│ X25519+ML-KEM+ChaCha+HMAC   │ token bucket · dummies    │
├─ null-transport ────────────┴─ null-memory ─────────────┤
│ Tor/I2P/Nym/PT + multiplexer│ mlock · wipe · HSM        │
├─ null-identity · null-group · null-tui · null-update ───┤
│ safety nums · MLS commits   │ Ratatui App · manifests   │
└─────────────────────────────┴─ null-core (types) ───────┘
```

### Cryptography — the Null Triple Ratchet (NTR)

- **Handshake**: Triple Diffie-Hellman (deniable — no signatures by default)
  combined with an ML-KEM-1024 encapsulation to the peer's long-term key.
- **Three ratchets, every session**:
  - *ECDH ratchet* — fresh X25519 ephemeral per message (rotate-before-send,
    so both sides always agree on `DH`).
  - *Kyber ratchet* — re-encapsulation to the peer's long-term ek every
    50 messages or 7 days; the fresh secret is mixed into the root key.
  - *Symmetric ratchet* — HKDF-SHA384 chain advanced per message.
- **Messages**: ChaCha20-Poly1305, counter nonce, associated data binding
  sender/receiver identities + protocol version.
- **Forward secrecy + PCS**: one-way chain evolution; classical healing after
  1 message, quantum healing at the next Kyber rekey.
- **Out-of-order delivery**: skipped chain-key cache (window 200, wiped on
  drop); replays and oversized gaps rejected.
- **Rekey loss recovery**: every message carries its PQ generation counter.
  A receiver that missed rekey frames buffers the message, requests a replay,
  and the initiator re-sends retained rekeys — lossless within the retention
  window; beyond it the session honestly reports that re-handshaking is needed.
- **Verified mode** (`--verified`): mutual ML-DSA-65 signatures over the
  handshake transcript, fingerprint pinning via the `i=` parameter
  (`ml-dsa:<sha3-256(vk)>`), and a canonical 12×5-digit safety number (plus
  scannable QR) that matches on both sides for out-of-band confirmation.

### Transports — censorship resistance

One async trait, six backends, latency-weighted election with transparent
failover. Live paths speak real protocols; absent daemons produce actionable
errors, never fake connectivity:

- **Tor**: SOCKS5 dialing (`.onion` resolved remotely — no local DNS leak)
  plus control-port ephemeral onion provisioning (`ADD_ONION`).
- **I2P**: SAMv3 sessions + stream connects.
- **Nym**: SOCKS5 through the local nym-client gateway.
- **Snowflake / WebTunnel / obfs4**: managed sidecar binaries with torrc
  bridge guidance.
- **Loopback**: in-memory circuit for the self-test demo.
- Length-prefixed blob pipes, goodbye handshake + 2s drain on quit so no
  peer ever loses in-flight messages to a TCP RST.

### Traffic-analysis resistance

Every network frame is exactly **2048 bytes**
(`ver ‖ type ‖ counter ‖ len ‖ reserved ‖ payload ‖ random padding`).
A token bucket (1 frame/2s base, burst 5, truncated-normal jitter) shapes
sends, and indistinguishable dummy frames provide cover traffic while idle —
including in live chats.

### Memory & endpoint hardening (Linux-first, OS abstractions ready)

- `mlock`, `MADV_WILLNEED`/`MADV_DONTDUMP`, `PR_SET_DUMPABLE=0`.
- 3-pass panic wipe (random → zero → random) on `SIGINT`/`SIGTERM`/`SIGHUP`,
  panic, Ctrl-C, `/quit`, EOF, peer goodbye, USBGuard trigger.
- Alternate-screen TUI with scrollback kill on exit; clipboard copy with
  5-second auto-clear and clipboard-manager warnings.
- HSM tiers: Tier-1 RAM-only default; TPM/YubiKey presence probe
  (`--hsm check`); device-bound local-secret mixing. The shared ratchet root
  is deliberately *never* mixed with device-local material (peers could not
  converge) — the HSM guards local identity secrets.

### Groups (Null-MLS TreeKEM)

Real ratchet tree with PQ (ML-KEM-1024) node keys: every commit refreshes
the committer's direct path and encrypts each path secret to the sibling
subtrees' resolutions — **O(log n) encapsulations** (proven: 3 bundles at
depth 3 for 8 members, vs 8 one-per-member). Removals blank nodes
(resolution routes around blanks); epochs hash-chain (`prev_hash`), so
forks, gaps, and replays are rejected; Welcomes carry roster + public tree
+ joiner path. Up to 50,000 members.

### Updates

Hybrid-signed manifests (Ed25519 + SLH-DSA-SHA2-128s, both mandatory;
monotonic version; binary + lockfile hashes; downgrade rejection)
distributed over onion fetches
and signature-checked P2P gossip where newest-verified wins.

---

## Quickstart

```bash
cargo build --locked --bin null
```

**Self-test demo** (handshake → frames → shaper → decrypt, no daemons):

```bash
./target/debug/null --peer loopback
./target/debug/null --peer loopback --tui        # full-screen Ratatui UI
./target/debug/null --peer loopback --verified   # ML-DSA mutual auth demo
```

**Two-process chat** (two terminals, same machine or Tor-fronted):

```bash
# Terminal 1: serve one inbound handshake, print your null:// string
./target/debug/null --listen 18080
# Terminal 2 (add --verified on both for mutual authentication):
NULL_DIRECT_ADDR=127.0.0.1:18080 ./target/debug/null --peer 'null://…'
# ...or with a full-screen UI on either side:
./target/debug/null --listen 18080 --tui
```

Over real Tor, front the listener's port with an onion service
(`--control-port 9051` provisions one automatically) and dial with
`NULL_LIVE_TRANSPORT=1`.

**In-chat commands**: `/quit` (goodbye + drain + wipe) · `/lock` · `/unlock` ·
`/copy` (copies last peer message, clears clipboard in 5s). TUI adds
demo PIN `1234` / duress `0000`, Esc to quit.

**Connection strings** (`null://`):

```
null://<56-char-onion>.onion?k=<base64 ML-KEM-1024 ek>&i=<ml-dsa:fingerprint>&t=tor,i2p,nym
```

---

## CLI reference

```
--peer <null://…|loopback>   peer to dial (omit to idle)
--listen <PORT>              responder mode on 127.0.0.1:PORT
--verified                   ML-DSA-65 mutual auth + safety number + QR
--deniable                   (default) strip all signature material
--tui                        full-screen Ratatui interface (loopback or live)
--transports <list>          priority order (default tor,i2p,nym)
--control-port <PORT>        provision ephemeral onion via Tor control
--secure-input               evdev keystroke reading (needs root)
--usbguard                   panic-wipe on new /dev nodes
--auto-lock-secs <N>         idle lock (default 1800)
--dead-man-secs <N>          idle wipe + exit, 0 disables (default 0)
--safe                       decoy IRC-like interface (loopback/TUI sessions)
--hsm <software|check>       local-secret backend / hardware probe
```

---

## Verification

- **89 tests**, all passing: ratchet roundtrips, out-of-order bursts, rekey
  healing at message 51, lossless rekey-loss recovery, handshake codecs +
  fragmentation, TCP end-to-end (deniable *and* verified, incl.
  safety-number agreement), TreeKEM commits/openings/blanks, group
  Welcome/removal/fork-rejection, hybrid
  release signing, update gossip, TUI rendering + key routing, live-protocol
  stub servers, HSM binding, evdev keymap, key-transparency log,
  downgrade-attack matrix, deniability tripwire, DeviceSet management,
  3-process multi-device flow.
- **Live proofs**: scripted two-process chats (deniable, verified with pinned
  fingerprints, graceful goodbye/drain shutdown) and automated pty-driven
  TUI tests (loopback and live listener). Quitting can no longer RST away a
  peer's in-flight messages.
- **Reproducibility**: `cargo run -p xtask -- repro` builds twice and
  compares hashes (verified identical).
- **Gates**: `cargo fmt --check`, `cargo clippy --locked --all-targets
  -- -D warnings`, `cargo test --workspace`,
  `cargo xtask fuzz`, `cargo xtask kat --check`
  (see `.github/workflows/ci.yml` and `.github/workflows/tamarin.yml`).
- **Formal verification**: `model/handshake.spthy` proves establishment
  secrecy, initiator KCI resistance, and verified-PINNED mutual
  authentication for the handshake under Dolev-Yao + compromise
  (tamarin-prover 1.12.0, pinned, proven in CI — 5/5 lemmas). The ratchet
  phase (`model/ratchet.spthy`) is modelled line-for-line but its
  chain-update proofs are in progress (see its header). Scope and
  abstractions are documented in `model/README.md` — including what is
  explicitly NOT covered (deniability, anonymity, side channels, groups,
  deniable-responder KCI which is false by construction).
- **Known-answer vectors**: `vectors/` commits deterministic outputs
  (X25519 cross-checked with OpenSSL, HKDF-SHA384 with an independent
  Python implementation) so others can cross-implement; drift fails CI.

### Standards mapping

NIST FIPS 203 (ML-KEM-1024) · FIPS 204 (ML-DSA-65) · FIPS 205
(SLH-DSA-SHA2-128s hybrid release signatures, both mandatory) ·
MLS-inspired group commits (RFC 9420 family) · Apple PQ3
Level-3-style ongoing rekeying · SLSA-style reproducible builds.

---

## Limitations & roadmap

- Nightly-only harnesses (miri, cargo-fuzz with sanitizers) remain future
  work. A deterministic stable fuzz corpus (`cargo xtask fuzz`, wired
  into CI) covers every wire decoder today, and the Tamarin handshake
  model (`model/handshake.spthy`, proven in CI) covers establishment;
  ratchet proofs are in progress with behavior covered by tests + KATs.
- Group commits are O(log n) TreeKEM path commits (proven by test: 3 bundles
  at depth 3 for 8 members). Remaining scaling work is operational (large-group
  fan-out batching), not cryptographic.
- Bridge transports need operator-provided sidecars/bridges.
- Secure Enclave support is macOS-gated scaffolding; TPM/YubiKey key
  *operations* need their native stacks (detection is implemented).

---

## Design docs

- `docs/deniability.md` — what deniable mode guarantees (and plainly does
  not), enforced by a frame-level tripwire test.
- `docs/multidevice.md` — one identity across N devices: transcript-bound
  device ids, fan-out, group revocation, and stated limits.

## License

MIT OR Apache-2.0. Post-quantum privacy is for everyone.
