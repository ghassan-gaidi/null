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
# Hermetic install (Linux), sha256-pinned Maude 3.5.1 + prover 1.12.0:
./model/prover-install.sh [dest]        # writes <dest>/env.sh + pins.sha256
source prover-env/env.sh                # PATH + MAUDE_LIB

# Prove the handshake theory and parse-check the rest:
tamarin-prover --prove model/handshake.spthy
tamarin-prover --prove=mutual_agreement model/handshake.spthy
tamarin-prover --parse-only model/ratchet.spthy
tamarin-prover --parse-only model/ntr.spthy
```

### Hermetic prover toolchain

`model/prover-install.sh` rebuilds the exact prover environment CI uses:
Maude 3.5.1 + tamarin-prover 1.12.0, both downloaded from pinned
releases and **sha256-verified against the same digests as
`.github/workflows/tamarin.yml`** — a substituted download fails loudly
instead of silently proving the wrong thing. The installed tree records
its checksums in `pins.sha256`, and

```bash
cargo run --locked -p xtask -- prover --check   # release ceremony gate
```

verifies that the pinned install is intact and both binaries run (Maude
on PATH/MAUDE_LIB exactly as `env.sh` sets them), failing the release
ceremony if anything is missing or tampered with. `NULL_PROVER_DIR` or a
path argument overrides the default search (`./prover-env`, `/tmp/prover`).

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
