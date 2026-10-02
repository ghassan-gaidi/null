# Security posture

The single, honest statement of what Null proves, what it relies on, and
what it does not claim — for auditors, reporters (see `SECURITY.md`), and
operators deciding whether to trust it. Everything here is either enforced
by a gate or explicitly a limitation.

## 1. Posture in one paragraph

Null is a **design-confident, formally verified at the establishment
layer** messenger: the handshake is machine-proven (5/5 Tamarin lemmas,
CI-enforced); the ratchet phase is modelled but not yet machine-proven
(100 tests + KATs + fuzz in the meantime); the transport/endpoint story is
engineered and tested but has *not* been hardened by a third-party audit,
side-channel measurement (`dudect`), sanitizer fuzzing, or unbounded
adversarial review. Use of `--verified` + out-of-band `i=` pinning is the
only mode in which `mutual_agreement` is claimed. Everything below the
first three rows of the table is a **limitation or a mitigation**, not a
proof.

## 2. Summary table

| Guarantee | Status | Evidence |
|---|---|---|
| Handshake establishment secrecy | **Proven** (Dolev-Yao + compromise) | Tamarin `root_secrecy`, CI |
| Initiator KCI resistance | **Proven** | Tamarin `kci_initiator`, CI |
| Verified-PINNED mutual agreement | **Proven** (pin required; TOFU excluded by design) | Tamarin `mutual_agreement` + `vk_echo`/stale-ek/pinning tests |
| Ratchet secrecy / FS / PQ-PCS | **In progress** (modelled; not machine-proven) | `model/ratchet.spthy`, tests + KATs |
| Deniability (default mode) | Classical argument + tripwire test; OE proof **not claimed** | `docs/deniability.md` |
| Downgrade resistance | Tested (10-case matrix) | `downgrade.rs` |
| Decoder robustness | Tested (deterministic corpus) | `cargo xtask fuzz` |
| Deterministic primitive outputs | Tested (byte-for-byte) | `cargo xtask kat --check` |
| Reproducible builds | Tested (bit-identical) | `cargo xtask repro` |
| Memory safety of `unsafe` (15 sites) | Reviewed in-repo only; **miri not run** (nightly) | `docs/audit-scope.md` |
| Constant-time message paths | **Not measured** (`dudect` not run) | — |
| Sanitizer fuzzing | **Not run** (cargo-fuzz needs nightly) | stable corpus shipped instead |
| Third-party audit | **Not performed** | open invitation; `docs/audit-scope.md` is the brief |

## 3. Key policies that bound the guarantees

- **Rekey cadence is a security parameter**: classical ECDH is
  quantum-vulnerable, so Harvest-now-decrypt-later exposure is bounded by
  the Kyber re-encapsulation rate — every `50` messages or `604800`
  seconds (7 days), whichever comes first, counted by both sides. Under a
  fully passive adversary this determines how long a captured ciphertext
  stream is safe against a future quantum computer.
- **Authenticated rekey matters**: rekey ciphertexts are unauthenticated
  (injection = DoS/desync, never key leakage); the session fails loud
  (re-handshake demand) via the resync state machine rather than silently
  diverging or degrading.
- **Pinning is the authentication mechanism**: `i=<ml-dsa:fingerprint>`
  in `null://` + out-of-band verification. TOFU accepts any vk and yields
  **no agreement guarantee** — the UI says so, and the Tamarin model
  proves agreement only for the PINNED case.
- **The responder's key must be the advertised key**: verified finalize
  refuses stale `k=` responses; deniable finalize falls back silently by
  design (documented weaker path).
- **Quantum PCS latency**: post-compromise healing is classical after 1
  message (ECDH ratchet) and quantum at the next Kyber rekey — that can be
  up to 50 messages later.
- **Loss is bounded and loud**: `MAX_SKIP = 200` (out-of-order), `8`
  retained rekeys, `16` pending, `3` resync rounds — beyond those, refuse
  to continue rather than diverge.

## 4. Trust anchors (assumed sound)

1. Toolchain + crates.io (mitigated by `Cargo.lock`, `--locked`,
   reproducible builds — not eliminated).
2. OS kernel (mlock, ptrace scope, `/dev` access control).
3. Transport daemons (sidecars remain operator integrity; E2E is
   independent of them).
4. User performs out-of-band verification at least once.
5. `OsRng`/kernel CSPRNG.

## 5. Hardening status by area

| Area | Shipped | Gap |
|---|---|---|
| Memory | RAM-only, mlock/MADV_DONTDUMP, 3-pass wipe, no disk writes | cold boot with power retained, live-process scraper |
| Terminal | alternate screen, scrollback kill, `/dev/tty` input | terminal keyloggers (mitigated by `--secure-input`) |
| Clipboard | auto-clear in 5 s, manager warnings, zombie reaping | managers that snapshot history |
| Input | evdev secure input (root) | needs root; TUI ignores it |
| Coercion | duress PIN, decoy mode, USBGuard, dead-man | rubber-hose, not a proof |
| HSM | Tier-1 software binding; Tier-2 probe | **native TPM/YubiKey/SE key ops not linked** — do not treat the probe as a key-isolation boundary |
| Transport | Tor/I2P/Nym dialing, PT bridge templates, shaping, dummies | metadata rides the transport's own anonymity; bridge sidecars are operator-run |
| Updates | hybrid Ed25519+SLH-DSA, monotonic floor, gossip | onion fetch channel is roadmap; release-key compromise is catastrophic by design |
| Supply chain | lockfile, `--locked`, repro, `cargo-audit` + `cargo-deny` gates in `supply-chain.yml` (license allow-list, sources, advisories, duplicate/bans) | sigstore/SBOM are release-process targets, not shipped; SBOM contents self-certify one level of the toolchain |

## 6. Known bugs / edge cases (behave as designed, but be aware)

- TUI quit path (`Esc`) sends goodbye + drains inbound (~2 s) before wipe,
  matching line-mode `/quit` (parity fixed; a TUI peer now sees an orderly
  goodbye).
- `--tui --secure-input` is rejected at startup: evdev grabbing feeds the
  line-mode reader only, so the combination fails closed instead of
  silently running on terminal input.
- Deniable `finalize` fails closed on an empty responder ek echo (parity
  with verified mode's hard fail; honest responders always echo).
- Receive-side rekeys: a mostly-silent peer still fires a rekey on its own
  next send after 50 received messages.
- The `listener`/`NULL_DIRECT_ADDR` escape hatch is a test hook — real
  peers must use `.onion` hosts.

## 7. Audit roadmap (ordered)

1. **Ratchet proofs** (`model/ratchet.spthy`): oracle/sources-annotated
   `executable`, `rekey_executable`, `msg_secrecy_no_compromise`,
   `forward_secrecy`, `pcs_after_rekey`.
2. **Third-party protocol review** against `docs/audit-scope.md` + this
   page.
3. **miri** over the 15 unsafe sites (needs nightly anyway).
4. **dudect / ctgrind** on message-key derivation + AEAD paths.
5. **Sanitizer fuzz** (cargo-fuzz + ASan/UBSan) once a nightly harness is
   acceptable.
6. **Wycheproof-style** ML-KEM/ML-DSA cross-checks (`vectors/README.md`).
7. **Release posture**: SBOM, sigstore/cosign attestation, onion update
   channel.

Status changes to any row above must be reflected here, in `SUMMARY.md`,
`README.md`, and `model/README.md` at the same time.