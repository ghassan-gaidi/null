# Audit scope — Null v2.0 protocol core

Intended for an independent reviewer. Total protocol core is small by
design; review it in the order below.

## 1. In scope (priority order)

| # | Target | Lines (approx) | Why first |
|---|---|---|---|
| 1 | `crates/null-crypto/src/lib.rs` — handshake, NTR ratchet, rekey | ~700 | All session security reduces to this file |
| 2 | `crates/null-session/src/lib.rs` — framing pipeline, Inbox recovery | ~400 | Generation checks + resync state machine |
| 3 | `crates/null-group/src/lib.rs` + `tree.rs` — TreeKEM commits | ~900 | Most complex state machine; newest code |
| 4 | `crates/null-update/src/lib.rs` — hybrid release signatures | ~200 | Supply-chain trust root |
| 5 | `model/handshake.spthy` (verified 5/5) + `model/ratchet.spthy` (modelled, proofs in progress) + `model/README.md` | ~300 | Check model↔code correspondence (§5 below) |
| 6 | `crates/null-memory/src/lib.rs` (`unsafe` blocks) | ~150 | Memory-safety of wipe/mlock paths |

Explicitly **out of scope for a crypto audit**: TUI rendering, CLI arg
parsing, transport dialers (reviewed separately as network code),
evdev ioctl handling (root-only, defense-in-depth feature).

## 2. Adversary model assumed by the code

Dolev-Yao network attacker (read/drop/inject/replay) + post-compromise
state reveals + harvest-now-decrypt-later quantum adversary + malicious
(but non-colluding) group members for TreeKEM paths. NOT assumed:
endpoint compromise beyond user level, side channels (see §4), malicious
compiler/registry (mitigated by lockfile + reproducible builds, not
eliminated).

## 3. Properties claimed (with where each is enforced)

- Establishment secrecy without compromise: Tamarin `root_secrecy` (handshake).
- Initiator KCI resistance: Tamarin `kci_initiator` (handshake). There is
  deliberately NO deniable-responder KCI lemma — false by construction
  (anyone can encapsulate to B and compute the root); see the theory header.
- Verified-PINNED mutual agreement: Tamarin `mutual_agreement` (handshake)
  + pinning/echo/stale-ek/degenerate-rejection tests. TOFU mode explicitly
  excluded from the agreement claim.
- Ratchet message secrecy / forward secrecy / quantum PCS after Kyber
  rekey: `model/ratchet.spthy` states them but automated proving of the
  chain-update loop is in progress; enforced today by unit tests, KAT
  vectors, and the fuzz corpus (see the theory header).
- Deniability (default mode): `docs/deniability.md` + frame tripwire test
  (observational-equivalence proof explicitly NOT claimed).
- Group PCS on removal, fork/gap/replay rejection: TreeKEM tests.
- No silent downgrade: `downgrade.rs` 10-case matrix.

## 4. Known gaps (do not file these as findings; verify the docs match)

- No constant-time verification of message paths (`dudect` not run).
- No fuzzing with sanitizers (stable-only `xtask fuzz` corpus instead).
- TreeKEM is MLS-shaped, not RFC 9420; no interop claim.
- Rekey ciphertexts are unauthenticated: injection causes desync (DoS),
  never key leakage; the session fails loud (re-handshake demand).
- `unsafe` surface: 15 sites, documented per-site in code comments.

## 5. Model↔code correspondence checklist

For each item, confirm the Tamarin abstraction matches the Rust:
- [ ] `kempk/kenc/kdec` equation ⇔ `KyberKeypair::{encapsulate,decapsulate}` (separate from signing `pk`, as in code)
- [ ] `root = h(<dh3, kq, 'root'>)` ⇔ `initial_root_key`
- [ ] pinned `(ek, vk)` directory pair for the same `$B` ⇔ `null://` `k=`+`i=` with `expected_fp` pinning; echo `vkA` ⇔ `vk_echo`; attested `ek` ⇔ stale-key fail-closed
- [ ] degenerate peer/DH-output rejection ⇔ `EphemeralKey::diffie_hellman` + `NonDegeneratePeer` restriction
- [ ] rotate-before-send DH term equality ⇔ `encrypt`/`decrypt` order
- [ ] chain advance `h(<chain,'chain'>)` ⇔ `advance_chain`
- [ ] rekey mixes fresh `k_new` into root, chain untouched ⇔ `mix_kyber_shared`
- [ ] verified transcripts ⇔ `signing_msg` (init + response, incl. device id)
- [ ] generation counters/gossip NOT modelled (loss recovery is
      availability-only; confirm it cannot affect key secrecy)

## 6. How to verify locally

```bash
cargo test --workspace --locked          # 90 tests
cargo xtask fuzz 20000                   # decoder corpus
cargo run -p xtask -- repro              # bit-identical builds
tamarin-prover --prove model/handshake.spthy   # 5/5 lemmas (needs Maude 3.5.1, see model/README.md)
tamarin-prover --parse-only model/ratchet.spthy
```
