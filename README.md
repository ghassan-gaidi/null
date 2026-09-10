# Null — Post-Quantum, Metadata-Resistant Terminal Messenger

[![CI](https://github.com/ghassan-gaidi/null/actions/workflows/ci.yml/badge.svg)](https://github.com/ghassan-gaidi/null/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

**Null** is a zero-telemetry, serverless, post-quantum peer-to-peer terminal
messenger. It runs entirely in volatile RAM, leaves zero forensic residue, and
provides **Level 3 post-quantum messaging security**: ongoing post-quantum
rekeying inside a continuous triple ratchet, multi-transport censorship
resistance, and hardware-aware key isolation — all in a terminal-native app.

Everything below is implemented and tested in this repository: 60 tests green,
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
| Multi-transport: Tor / I2P / Nym / Snowflake / WebTunnel / obfs4 | ✅ | ❌ |
| Fixed 2048-byte frames + token-bucket shaping + dummy cover | ✅ | ❌ |
| RAM-only, mlock, 3-pass panic wipe, no disk writes | ✅ | ❌ |
| Duress PIN, decoy mode, USBGuard, auto-lock, clipboard auto-clear | ✅ | ❌ |
| Group messaging with PCS-preserving commits | ✅ | ✅-ish |
| Signed, gossip-distributed, downgrade-proof updates | ✅ | ❌ |
| Reproducible builds (verified in CI-able `xtask`) | ✅ | Rare |

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

### Groups (Null-MLS)

Tree-secret evolution with PQ KeyPackages: Kyber-sealed `Welcome` envelopes
for joiners (with roster sync) and per-member commit envelopes on removal
(true PCS — the removed member cannot open the new epoch). Epochs hash-chain
(`prev_hash`), so forks, gaps, and replays are rejected, never silently
accepted. Up to 50,000 members.

### Updates

Ed25519-signed manifests (monotonic version, binary + lockfile hashes,
real SLH-DSA-SHA2-128s + Ed25519 hybrid signatures, downgrade rejection)
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
--safe                       decoy IRC-like interface
--hsm <software|check>       local-secret backend / hardware probe
```

---

## Verification

- **60 tests**, all passing: ratchet roundtrips, out-of-order bursts, rekey
  healing at message 51, lossless rekey-loss recovery, handshake codecs +
  fragmentation, TCP end-to-end (deniable *and* verified, incl.
  safety-number agreement), group Welcome/removal/fork-rejection, hybrid
  release signing, update gossip, TUI rendering + key routing, live-protocol
  stub servers, HSM binding, evdev keymap.
- **Live proofs**: scripted two-process chats (deniable, verified with pinned
  fingerprints, graceful goodbye/drain shutdown) and automated pty-driven
  TUI tests (loopback and live listener). Quitting can no longer RST away a
  peer's in-flight messages.
- **Reproducibility**: `cargo run -p xtask -- repro` builds twice and
  compares hashes (verified identical).
- **Gates**: `cargo fmt --check`, `cargo clippy --locked --all-targets
  -- -D warnings`, `cargo test --workspace` (see `.github/workflows/ci.yml`).

### Standards mapping

NIST FIPS 203 (ML-KEM-1024) · FIPS 204 (ML-DSA-65) · FIPS 205 slot reserved
(SLH-DSA-SHA2-128s, verified) · MLS-inspired group commits (RFC 9420 family) · Apple PQ3
Level-3-style ongoing rekeying · SLSA-style reproducible builds.

---

## Limitations & roadmap

- Formal protocol models (Tamarin/ProVerif) and nightly-only harnesses
  (miri, cargo-fuzz) are the next track. A deterministic stable fuzz corpus
  (`cargo xtask fuzz`, wired into CI) covers every wire decoder today.
- Group commits are O(n) re-encapsulations rather than O(log n) TreeKEM
  path secrets — fine for typical groups, not yet 50k-optimal.
- Bridge transports need operator-provided sidecars/bridges.
- Secure Enclave support is macOS-gated scaffolding; TPM/YubiKey key
  *operations* need their native stacks (detection is implemented).

---

## License

MIT OR Apache-2.0. Post-quantum privacy is for everyone.
