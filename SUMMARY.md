# Null — Design & Verification Specification v2.0

> Post-quantum, metadata-resistant, serverless peer-to-peer terminal
> messenger. Everything below describes what the repository *does*, what is
> *proven*, and what is *explicitly not claimed*. Statements marked
> "❨target❩" are roadmap goals, not shipped behavior.

## 1. Executive Identity

**Null** is a zero-telemetry, serverless, post-quantum peer-to-peer
terminal messenger. It runs entirely in volatile RAM, leaves no forensic
residue on disk, and provides **ongoing post-quantum rekeying inside a
continuous triple ratchet** — the Apple PQ3 Level-3-style property — plus
multi-transport censorship resistance (Tor / I2P / Nym / Snowflake /
WebTunnel / obfs4), hardware-aware key isolation, and a formally verified
establishment layer.

Proof status, stated plainly, in one paragraph:

- **Engineered & tested**: 105 tests green, `clippy -D warnings` clean,
  committed known-answer vectors, a stable-channel deterministic fuzz
  corpus over every wire decoder, live two-process chats (deniable,
  verified, TUI) proven over real sockets, and bit-identical reproducible
  builds via `cargo xtask repro`.
- **Formally verified**: the handshake is proven in the Dolev-Yao model
  with tamarin-prover (5/5 lemmas, enforced in CI) — establishment
  secrecy, initiator KCI resistance, and PINNED mutual authentication.
- **In progress**: the ratchet phase is modelled line-for-line
  (`model/ratchet.spthy`) but its chain-update proofs do not yet close
  automatically; today it is covered by tests, KATs, and fuzz, and the
  README/docs say exactly that.

---

## 2. Threat Model & Adversarial Assumptions

| Adversary Class | Capabilities | Null's posture |
|---|---|---|
| Passive network observer | Global traffic analysis, timing correlation, packet inspection | Defended: fixed 2048-byte frames, token-bucket shaping, dummy cover, Tor/I2P/Nym routing |
| Active network attacker | MitM, injection, replay, rushing, dropping | Defended: AEAD + bound associated data, per-message ratchet, transcript resync bounds, loss = loud failure |
| Quantum adversary (HNDL) | Stores ciphertexts today; breaks classical crypto later | Defended: ML-KEM-1024 now + periodic re-encapsulation (50 msgs / 604800 s); ML-DSA-65 + SLH-DSA are believed quantum-resistant |
| Local forensic analyst | Disk imaging, swap analysis, cold boot | Defended (partially): zero disk writes, `mlock`/`MADV_DONTDUMP`, 3-pass wipe; cold boot with power retained is made expensive, not defeated |
| Suppressive actor | Coercion, device seizure, rubber-hose | Mitigated: duress PIN, decoy mode, dead-man switch, alarm-level wipe; no crypto resists torture against *future* messages |
| Malicious group member | Reads group traffic, sends crafted commits | Defended: TreeKEM with blank-node removal, epoch hash-chaining, fork/gap/replay rejection. Insider *availability* denial is not claimed |
| Malicious update distributor | Serves crafted manifests/binaries | Defended: hybrid Ed25519 + SLH-DSA signatures (both mandatory), monotonic version, downgrade floor |
| Supply chain attacker | Compromised registry/build/, substituted binary | Mitigated: pinned `Cargo.lock`, reproducible builds verified bit-identical, signed manifests. A malicious compiler/registry is out of scope, as it is for every toolchain |
| Endpoint malware (user level) | Keyloggers, screen capture, memory scrape of the live process | Mitigated: evdev secure input, clipboard hygiene, anti-dump; a live-process scraper wins, stated plainly |
| Endpoint malware (root/kernel) | Everything | **Out of scope** — for every messenger |

### Trust assumptions (explicit)

1. The Rust toolchain, crates.io registry, and pinned dependency tree are
   honest (mitigated by `Cargo.lock` + reproducible builds, not eliminated).
2. The OS kernel enforces `mlock`, `madvise`, and ptrace scope correctly.
3. Transport daemons are the genuine articles. Traffic stays end-to-end
   encrypted regardless; sidecar integrity is the operator's job.
4. The user verifies fingerprints / safety numbers out-of-band at least
   once. TOFU (no `i=` pin) provides no agreement guarantee — the UI says
   so on every TOFU connect.
5. Randomness (`OsRng` / kernel CSPRNG) is sound.

### Non-goals, by design

- Anonymity against a global passive adversary beyond what the transport
  provides.
- Protection of plaintext from the peer (screenshots, testimony),
  or post-quantum deniability in the strong academic sense — the classical
  deniability argument is documented in `docs/deniability.md`.
- Forward secrecy against an adversary that *continuously* exfiltrates live
  session state (ratchets heal point compromises, not permanent implants).
- Hiding that Null is running (no binary steganography).

---

## 3. System Architecture

```
┌─ null-cli ─────────────────────────────────────────────────┐
│ flags · listener/initiator · line REPL · Ratatui TUI       │
├─ null-session ─────────────────────────────────────────────┤
│ handshake framing+reassembly · pack/unpack · Inbox recovery│
├─ null-crypto ───────────────┬─ null-frame ─────────────────┤
│ NTR triple ratchet          │ 2048B frames · token bucket  │
│ X25519+ML-KEM+ChaCha+HKDF   │ fixed padding · dummies      │
├─ null-transport ────────────┴─ null-memory ────────────────┤
│ Tor/I2P/Nym/PT + multiplexer│ mlock · 3-pass wipe · HSM    │
├─ null-identity · null-group · null-tui · null-update ──────┤
│ safety nums · TreeKEM       │ Ratatui App · signed updates │
└─────────────────────────────┴─ null-core (truth) ──────────┘
```

- `null-core` is the single source of truth for protocol versioning, frame
  geometry, rekey policy, transport kinds, and `null://` connection-string
  parsing.
- 12 workspace members (`resolver = "2"`, edition 2021, `rust-version`
  1.75, license MIT OR Apache-2.0).
- RAM-only by design: no database, no config files, no session logs, no
  disk writes at any layer.

---

## 4. Cryptographic Protocol: the Null Triple Ratchet (NTR)

### 4.1 Terminology — why "triple"

The "triple" refers to **three ratchet mechanisms** per session, not to
three DH computations:

| Ratchet component | Source | Rekey trigger | Quantum resistance |
|---|---|---|---|
| ECDH ratchet | Fresh X25519 ephemeral per message | Every sent message (rotate-before-send) | Classical only |
| Kyber ratchet | ML-KEM-1024 re-encapsulation to the peer's long-term ek | Every 50 messages or 604800 s (7 days), counted on **both** sides | Post-quantum |
| Symmetric ratchet | HKDF-SHA384 chain advancement | Every message | Post-quantum once the root is PQ |

### 4.2 Handshake (X25519 + ML-KEM-1024)

Deniable by default (no long-term signatures on the wire):

```
Peer A                                           Peer B
------                                           ------
EK_A = X25519 ephemeral                          (long-term Kyber keypair pre-generated)
(c, k_kyber) = ML-KEM-1024 encapsulate(ek_B)     (long-term ek advertised in null:// k=)
send: EK_A.pub ‖ c ‖ ek_A ‖ device_id  ──────►
                                                  decap c → k_kyber ; generate EK_B
◄────────────────────  EK_B.pub ‖ ek_B ‖ device_id ‖ vk_echo?

shared = X25519(EK_A.priv, EK_B.pub)   (a single ECDH, "DH3" in 3DH terms;
                                        DH1/DH2 with long-term keys are OMITTED
                                        in deniable mode — the price of repudiation)
root   = HKDF-SHA384(ikm = shared ‖ k_kyber, salt = 0³⁴⁸,
                     info = "Null-v2.0-initial-root-key")   → 48 bytes
```

The product is *3DH-style* (deniable one-ECDH establishment) plus an
ML-KEM-1024 quantum layer. The Tamarin model proves this exact equation.

**Verified mode (`--verified`, opt-in and loud):** both sides attach an
ML-DSA-65 verification key and a deterministic signature over the full
transcript (`signing_msg`, incl. `device_id` and the responder's current
long-term ek). The responder must echo the initiator's vk (`vk_echo`) —
the unknown-key-share guard — and return the exact advertised Kyber key
(stale `null://` string fails closed). The initiator may pin the peer's
fingerprint via the `i=` parameter (`ml-dsa:<sha3-256(vk)>`); without
pinning, agreement is TOFU and is *not* claimed as a proof.

- ML-KEM-1024: ek 1568 B, ciphertext 1568 B.
- ML-DSA-65: verification key 1952 B, signature 3309 B.
- `device_id`: 16 bytes, all-zero = unbound (legacy single-device).
- Sizes are why handshakes fragment: 1568+1568 B of Kyber material cannot
  fit a single 1984-byte payload, so inits cross two frames.

### 4.3 Message encryption

- AEAD: ChaCha20-Poly1305, 256-bit keys derived per message via
  `HKDF-SHA384(root ‖ chain ‖ counter ‖ ecdh ‖ kyber_shared, 0³⁴⁸,
  "Null-v2.0-message-key")` → 32 B.
- Nonce: 12 bytes, `[0u8;4] ‖ counter.to_be_bytes()`.
- Associated data: the session layer binds
  `"{sender}|{receiver}|{PROTOCOL_VERSION}"` (onion labels) or the hex
  long-term Kyber eks (`docs/wire-protocol.md`), so a message cannot be
  replayed into another direction or version.
- Wire format: `counter(8) ‖ kyber_generation(8) ‖ ecdh_pub(32) ‖
  ciphertext` — every message carries its PQ generation for loss detection.

### 4.4 Key timeline, forward secrecy, PCS

- One-way HKDF chains give forward secrecy: compromise of current keys
  does not reveal past message keys.
- Classical post-compromise security after **1 message** (fresh ECDH
  ephemeral on both sides); quantum PCS at the **next Kyber rekey**.
- Recovery bounds, independent and not to be conflated:
  - skipped-jump window `MAX_SKIP = 200` (chain keys cached, wiped on drop);
  - retained rekeys `RETAINED_REKEYS = 8` for loss replay;
  - pending undecryptable buffer `MAX_PENDING = 16` and
  - hard resync cap `MAX_REKEY_ROUNDS = 3` — beyond it the session
    demands a re-handshake instead of silently diverging.

### 4.5 Deniable & verified identity layer

- Default: no signature material anywhere on the wire.
- `--verified`: `IdentityKey` (32-byte seed, derived transiently),
  fingerprint `ml-dsa:<hex sha3-256(vk)>`, safety number
  `SHA3-256(canonical(vkA,vkB) ‖ session_id)` shown as 12 groups of 5
  digits, scannable QR, and an in-RAM key-transparency log that fails
  closed on key change.
- Deniable mode makes transcripts non-transferable (either peer could have
  forged every byte); it is **not** anonymity, and it is voided by
  `--verified` by design.

---

## 5. Transport & Traffic Analysis

### 5.1 Transports

Null dials **local daemons/sidecars** (never embedded Tor): SOCKS5 for
Tor (port 9050) and Nym (1080), SAMv3 for I2P (7656); Tor control (9051)
drives ephemeral onion provisioning (`ADD_ONION`). Snowflake, WebTunnel,
and obfs4 need operator-installed pluggable-transport sidecars (torrc
bridge guidance included); they fail closed, with remediation text, when
absent. Without `NULL_LIVE_TRANSPORT=1` dials validate the daemon port
(150 ms probe) and return virtual test circuits — live bytes only with the
flag set.

| Transport | Use case | Modeled latency (multiplexer election) |
|---|---|---|
| Tor | Baseline anonymity, onion rendezvous | 350 ms |
| I2P | Tor-blocked regions | 900 ms |
| Nym | Maximum metadata protection | 1400 ms |
| Snowflake | Active censorship (WebRTC bridges) | 700 ms |
| WebTunnel | DPI-heavy networks (HTTPS cover) | 420 ms |
| obfs4 | Bridge-level blocking | 380 ms |

The multiplexer elects by latency-weight with a 50 ms priority-rank
tie-break, and fails over transparently across all transports in priority
order.

### 5.2 Constant-size frames & shaping

- Every frame is exactly **2048 bytes**:
  `ver(2) ‖ type(1) ‖ counter(8) ‖ payload_len(4) ‖ reserved(17) ‖
  payload ‖ random padding`. Header 32 bytes; payload max **1984**;
  placement of the 16-byte Poly1305 tag is the caller's (encrypt-then-fit).
- Token bucket: 1 frame/2 s base (`SHAPER_BASE_INTERVAL_MS = 2000`,
  refill 0.5/s), burst **5**, inter-frame delay uniform 1.0–3.0 s
  (clamped 0.5–4.0 s) from a single uniform sample — timing does not
  fingerprint an RNG.
- Idle peers emit indistinguishable dummy frames (64 random bytes
  payload, same 2048-byte form) at the shaped rate in line and TUI modes.
- Frame types: `Data(0x01)`, `Dummy(0x02)`, `Control(0x03)`,
  `KyberRekey(0x04)`; any other type byte is rejected. Version mismatch
  (`PROTOCOL_VERSION = 0x0002`) is rejected at decode.

### 5.3 Connection lifecycle

Length-prefixed `u32 BE` blobs (≤ 16 MiB), 120 s receive timeout. On quit:
goodbye control frame, then ~2 s inbound drain — this is what guarantees a
peer's in-flight messages are never RST-discarded. On peer FIN/RST: drain,
then panic-wipe and exit 0.

---

## 6. Memory Hardening & Endpoint Security

- Zero disk writes; every sensitive buffer zeroized on drop.
- Linux: `mlock`, `MADV_DONTDUMP`, `PR_SET_DUMPABLE=0`; macOS/Windows
  abstractions ready (VirtualLock/mach_vm_wire scaffolding).
- 3-pass panic wipe (random → zero → random) on SIGINT/SIGTERM/SIGHUP,
  panic hook, Ctrl-C, `/quit`, EOF, peer goodbye, dead-man switch, and
  USBGuard trigger (new `/dev` node).
- Terminal: alternate screen, scrollback kill on exit, bracketed paste off
  by default; clipboard copy clears in **5 s** (`CLIPBOARD_CLEAR_SECS`)
  with clipboard-manager warnings; Wayland wl-copy zombies reaped.
- Secure input: optional `--secure-input` reads `/dev/input/event*`
  (root) to bypass terminal keyloggers; falls back to `/dev/tty` loudly.
- Duress/decoy: demo TUI PIN `1234`; duress PIN `0000` triggers wipe;
  `--safe` runs a benign IRC-like decoy surface; auto-lock default
  1800 s (`auto_lock_secs`); dead-man default disabled, `--dead-man-secs
  <N>` wipes+exits after N idle (default constant 1800 in `null-core`,
  CLI default 0).
- HSM tiers:
  - **Tier 1 (shipped)**: RAM-only `SoftwareHsm`; device-bound local
    secret mixing via `SHA384("Null-v2.0-hsm-bind:" ‖ context ‖
    machine-id ‖ secret)`. The shared ratchet root is deliberately *never*
    mixed with device-local material — peers could not converge; the HSM
    guards local identity secrets only.
  - **Tier 2 (probe)**: `--hsm check` detects TPM2 (`/dev/tpmrm0`,
    `/dev/tpm0`), YubiKey (`ykman`/`ykchalresp`), and Secure Enclave
    (macOS); native key *operations* need the vendor stacks, which are not
    yet linked. Detection reports honestly instead of silently
    downgrading. ❨target: tpm2-tss, ykman, SE SDK integration❩.

---

## 7. Groups — Null-MLS (TreeKEM)

- Complete binary ratchet tree in heap indexing; internal nodes carry
  ML-KEM-1024 keypairs derived deterministically from path secrets
  (HKDF-SHA384, labels `null-mls-node`/`null-mls-path`/`null-mls-root`).
- Commits refresh the committer's direct path, sealing each path secret to
  the sibling subtrees' **resolutions** (minimal non-blank cover) —
  **O(log n) encapsulations**, proven by test: 3 bundles at depth 3 for
  8 members (vs 8 one-per-member).
- Removal blanks the removed leaf and its off-path nodes; resolutions route
  around blanks (PCS for the remaining members). Epochs hash-chain
  (`prev_hash`), so forks, gaps, and replays are rejected (`"commit does
  not chain to current epoch"`). Removed members become `defunct` and all
  operations fail loudly.
- Welcome packages carry roster + public tree + joiner path, sealed to the
  joiner's KeyPackage ek via Kyber encapsulation + ChaCha20-Poly1305
  (`null-mls-welcome-wrap`). Roster, tree, and path arrive together (TOFU
  by necessity).
- Sender chains advance per member with `message_key = HKDF(tree_secret,
  salt=group_id, info=sender ‖ seq ‖ epoch)`; recipients prune chains so
  committers and receivers stay sequence-aligned.
- Limits and guards: up to **50000** members (`MAX_GROUP_MEMBERS`);
  declared depth capped at **20** at decode time (absurd-depth DoS guard);
  add/remove/bundle counts bounded on the wire. MLS-*shaped*, not RFC 9420;
  no interop claim.
- A malicious committer can always withhold commits (deny service) —
  availability from a malicious insider is not claimed.

---

## 8. Updates & Supply Chain

- **Hybrid signatures**: Ed25519 **and** SLH-DSA-SHA2-128s (FIPS 205)
  over `"{version}:{sha3_256_hex}"`; both must verify. Binary hash +
  `Cargo.lock` digest (`sha3_256_hex(cargo_lock)`) pinned in the manifest.
- **Downgrade floor**: `version < min_version` is rejected
  (`NullError::Downgrade`); offers must be strictly newer.
- **Distribution**: signature-checked P2P gossip (payload =
  `manifest ‖ 0x00 ‖ binary`, newest-verified wins regardless of who
  delivered it); manifests ≤ 1 MiB at parse.
  ❨target: primary distribution over a static `.onion` service — verify
  path exists, the fetch path is an integration point, not shipped❩.
- **Reproducible builds**: `cargo xtask repro` builds `--bin null` twice
  (isolated target dirs, `SOURCE_DATE_EPOCH=0`, `TZ=UTC`, `LC_ALL=C`) and
  compares SHA256 — verified bit-identical.
  ❨target: sigstore/cosign attestation of release binaries + SBOM — the
  signing scheme for manifests is shipped; artifact attestation is
  release-process work❩.
- **License hygiene**: MIT OR Apache-2.0 workspace-wide.

---

## 9. Formal Verification & Audit Status

The honest status table. "Proof" means an automated-verifier result; the
rest is covered by tests/KATs/fuzz and stated as such.

| Property | Tool | Status |
|---|---|---|
| Establishment secrecy (no KEM key leaked) | Tamarin `root_secrecy` | **Proven** (handshake) |
| Initiator KCI resistance | Tamarin `kci_initiator` | **Proven** (handshake) |
| Verified-PINNED mutual agreement | Tamarin `mutual_agreement` | **Proven** (handshake; TOFU excluded by design) |
| Honest deniable + verified runs complete | `hs_executable`, `verified_executable` | **Proven** (exists-trace sanity) |
| Ratchet message secrecy / FS / PQ-PCS after rekey | Tamarin (`model/ratchet.spthy`) | **In progress** — modelled line-for-line, chain-update proofs diverge under default heuristics; covered today by 105 tests, KAT vectors, fuzz |
| Deniability | `docs/deniability.md` + frame tripwire test | Classical argument documented; observational-equivalence proof **not claimed** |
| Deniable-responder KCI | — | **False by construction** (anyone can encapsulate to B); deliberately no lemma |
| TreeKEM PCS / fork / gap / replay | Tests | Chaos-tested, not machine-proved |
| No silent downgrade | `downgrade.rs` 10-case matrix | Tested |
| Memory safety of `unsafe` (15 sites) | Rust + audit-scope review | miri ❨target❩ — not run (nightly) |
| Constant-time message paths | dudect ❨target❩ | Not run |
| Sanitizer fuzzing | cargo-fuzz + ASan/etc. ❨target❩ | Stable-channel corpus shipped instead |

### Model↔code correspondence

Every abstraction the Tamarin models assume is checked against
`null-crypto` by same-named unit tests; the audit checklist lives in
`docs/audit-scope.md` §5. Anything the models do not cover (deniability,
anonymity, side channels, groups, loss recovery) is stated as out of scope
rather than silently assumed.

---

## 10. Operational Flow

```
$ null ──► bootstrap (transports, HSM, hibernation check)
         ──► discovery (paste peer's null:// · out-of-band)
         ──► handshake (deniable or verified-pinned)
         ──► NTR active: shaped 2048B frames + cover traffic
         ──► exit: goodbye + drain → 3-pass wipe → exit 0
```

In-chat: `/quit` (goodbye + drain + wipe) · `/lock` · `/unlock` ·
`/copy` (clipboard auto-clears in 5s). TUI: demo PIN `1234`, duress
`0000`, Esc quits, Ctrl-C wipes.

---

## 11. Standards & Framework Mapping

| Standard / Framework | Null's relation |
|---|---|
| NIST FIPS 203 (ML-KEM) | ML-KEM-1024 (Kyber-1024) at handshake + periodic rekey |
| NIST FIPS 204 (ML-DSA) | ML-DSA-65 opt-in verified identities |
| NIST FIPS 205 (SLH-DSA) | SLH-DSA-SHA2-128s hybrid release signatures |
| IETF MLS (RFC 9420 family) | **Inspired-by**, not conformant; no interop claim |
| Apple PQ3 Level 3 | Ongoing PQ rekeying inside a continuous ratchet — analogous, independently implemented |
| SLSA | Reproducible builds verified in-repo; attestation ❨target❩ |
| RFC 7748 / RFC 5869 / RFC 8439 | X25519, HKDF, ChaCha20-Poly1305 primitives |

---

## 12. SOTA Differentiators — Verified vs Target

| Capability | Null (shipped) | Null (target) | Mainstream E2E apps |
|---|---|---|---|
| Ongoing PQ ratcheting | ✅ Triple ratchet (ECDH+Kyber+chain) | — | ❌ |
| Multi-transport Tor/I2P/Nym/PT | ✅ Auto-failover | — | ❌ |
| Formal verification | ✅ Handshake, 5/5 lemmas | Ratchet proofs | Rare/partial |
| HSM key isolation | ✅ Tier-1 RAM + Tier-2 probe | Native TPM/SE/YubiKey ops | ✅ (mobile OS tiers) |
| Reproducible builds | ✅ Verified bit-identical | Sigstore + SBOM | ❌ |
| Hybrid-signed updates | ✅ Ed25519 + SLH-DSA, gossip | Onion fetch channel | ❌ |
| Terminal-native, zero GUI | ✅ Ratatui + line REPL | — | ❌ |
| Deniable by default | ✅ (classical argument) | PQ-deniability models | ❌ |
| Duress/decoy/USBGuard | ✅ | — | ❌ |
| Fixed-frame shaping + cover | ✅ | — | ❌ |

---

## 13. Source of Truth Map

| Topic | Where it lives |
|---|---|
| Protocol constants, frame geometry, rekey policy | `crates/null-core/src/lib.rs` |
| Handshake + ratchet + identity crypto | `crates/null-crypto/src/lib.rs` |
| Framing, shaping, dummies | `crates/null-frame/src/lib.rs` |
| Session pipeline, inbox recovery | `crates/null-session/src/lib.rs` |
| Transports, multiplexer, live dialing | `crates/null-transport/src/lib.rs` |
| Memory wipe, HSM, sleep protection | `crates/null-memory/src/lib.rs` |
| Safety numbers, transparency, device sets | `crates/null-identity/src/lib.rs` |
| TreeKEM groups | `crates/null-group/src/lib.rs` (+ `tree.rs`) |
| Signed updates, gossip | `crates/null-update/src/lib.rs` |
| Binary entry points | `crates/null-cli/src/main.rs`, `crates/null-tui/src/lib.rs` |
| Tamarin models | `model/handshake.spthy` (5/5 proven), `model/ratchet.spthy` (in progress), `model/ntr.spthy` (legacy) |
| KAT vectors | `vectors/` |
| Threat model, deniability, audit scope, ops | `docs/` |

**Null v2.0** is a provably-secure *establishment layer*, an engineered
triple-ratchet *message layer* under active formalization, a
censorship-resistant *transport layer*, and a RAM-only *endpoint story* —
with every gap between those claims and the code named in this document
and its companions in `docs/`.