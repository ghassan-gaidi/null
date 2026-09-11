# Tamarin models of Null (`model/`)

Symbolic verification of the handshake + ratchet core with
[tamarin-prover](https://tamarin-prover.com/) 1.12.0 (pinned; see
`.github/workflows/tamarin.yml`). The proof is split assume-guarantee so
each theory stays tractable; `ntr.spthy` is the legacy combined model,
kept for reference.

## What is proven (`model/handshake.spthy` — all verified, enforced in CI)

| Lemma | Property | Kind |
|---|---|---|
| `hs_executable` | Honest deniable run completes | exists-trace (sanity) |
| `verified_executable` | Honest verified (pinned) handshake completes | exists-trace (sanity) |
| `root_secrecy` | Establishment secrecy, neither KEM key leaked | all-traces |
| `kci_initiator` | Initiator KCI resistance (own KEM leak OK, peer not) | all-traces |
| `mutual_agreement` | Verified PINNED initiator agreement implies matching responder session, unless an identity key was revealed | all-traces (non-injective) |

Verified mode means PINNED: `null://` carries `i=<ml-dsa fingerprint>`,
the CLI passes it as `expected_fp`, and the model fetches the peer's
`(ek, vk)` directory pair for the same `$B`. TOFU (`expected_fp = None`)
accepts any vk and cannot provide agreement — by design. There is
deliberately NO deniable-responder KCI lemma: anyone can encapsulate to
`B`'s public ek and compute the resulting root, so the property is false
by construction (see the theory header); use verified + pinning for
authentication.

## In progress (`model/ratchet.spthy` — modelled, parse-checked in CI)

Per-message ECDH ratchet (rotate-before-send) + symmetric chain +
periodic Kyber re-encapsulation, with session/long-term compromise.
Intended lemmas (`executable`, `rekey_executable`,
`msg_secrecy_no_compromise`, `forward_secrecy`, `pcs_after_rekey`) are
stated in the file but automated proving of the chain-update loop
diverges under default heuristics — honest even-exists traces time out
while the static-chain variant proves in seconds. Until an
oracle/sources-annotated proof lands, ratchet behavior is covered by
`cargo test`, `vectors/` KATs, and `cargo xtask fuzz`.

## Run it

```bash
# Ubuntu: Maude 3.5.1 from the pinned zip, prover from the pinned 1.12.0 asset
# (sha256 verified in CI; see the workflow for exact commands).
tamarin-prover --prove model/handshake.spthy
# Single lemma, e.g.:
tamarin-prover --prove=mutual_agreement model/handshake.spthy
# Parse-check the rest:
tamarin-prover --parse-only model/ratchet.spthy
tamarin-prover --parse-only model/ntr.spthy
```

CI (`.github/workflows/tamarin.yml`) downloads the pinned prover release
(with sha256 check), installs Maude via apt, and proves the whole file
with a hard timeout. The job is separate from the main Rust CI so prover
flakiness can never mask a code regression — and vice versa.

## Scope and abstractions

Read the header comment of `ntr.spthy` first: it lists every modeling
abstraction with its soundness direction (counters, AEAD ideality, KEM
equation, named peers, no frame layer, ideal signatures, no groups).
Everything the model assumes is checked against `crates/null-crypto` by
the similarly-named unit tests; anything it does not cover (deniability,
anonymity, side channels, TreeKEM groups, update gossip) is stated as
out of scope rather than silently assumed.

## Status

Last proven locally + in CI: see the checklist in the theory header,
updated on every model change. If you touch the handshake, ratchet, or
rekey logic in `null-crypto`, re-run the prover before claiming coverage.
