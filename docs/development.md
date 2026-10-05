# Development guide

How to build, test, verify, and safely modify Null. This is the
plain-spoken companion to the marketing pages (`README.md`, `SUMMARY.md`).

## Workspace layout

12 members, `resolver = "2"`, edition 2021, `rust-version = 1.75`:

| Crate | Responsibility | Critical file |
|---|---|---|
| `null-core` | Protocol version, frame geometry, rekey policy, connection-string grammar, shared errors | `crates/null-core/src/lib.rs` |
| `null-crypto` | Handshake, Triple Ratchet, identity (ML-DSA), KEM, AEAD | `crates/null-crypto/src/lib.rs` |
| `null-frame` | 2048-byte frame codec, token-bucket traffic shaper, dummies | `crates/null-frame/src/lib.rs` |
| `null-session` | Handshake framing/reassembly, pack/unpack pipeline, Inbox recovery | `crates/null-session/src/lib.rs` |
| `null-transport` | Tor/I2P/Nym/PT dialing, multiplexer, blob pipes, live SOCKS/SAM | `crates/null-transport/src/lib.rs` (+ `live.rs`) |
| `null-memory` | mlock/MADV, 3-pass wipe, HSM tiers, sleep protection | `crates/null-memory/src/lib.rs` |
| `null-identity` | Safety numbers, QR, transparency log, device sets | `crates/null-identity/src/lib.rs` |
| `null-group` | TreeKEM ratchet trees, commits, welcomes | `crates/null-group/src/lib.rs` (+ `tree.rs`) |
| `null-update` | Hybrid-signed manifests, gossip, downgrade floor | `crates/null-update/src/lib.rs` |
| `null-tui` | Ratatui app, key routing, duress/decoy, clipboard | `crates/null-tui/src/lib.rs` |
| `null-cli` | Binary entry point, listeners, chat loops, wipe lifecycle | `crates/null-cli/src/main.rs` (+ `secure_input.rs`) |
| `xtask` | `repro` / `fuzz` / `kat` / `doccheck` release chores | `xtask/src/main.rs` |

`/home/leo/arsenal/Null` layout: `crates/`, `model/` (Tamarin), `vectors/`
(KATs), `docs/` (this documentation), `.github/workflows/`.

## Prerequisites

- Stable Rust ≥ 1.75 (`rustup toolchain install stable`).
- For Tamarin work only: `tamarin-prover 1.12.0` + `Maude 3.5.1` (sha256
  pins in `.github/workflows/tamarin.yml`; install steps in
  `model/README.md`). Everything else — including the entire CI Rust gate
  set — runs on a plain stable toolchain with no system dependencies.

## The full gate set (all required before merge)

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --workspace --locked
cargo run --locked -p xtask -- fuzz          # deterministic decoder corpus (20k iters default)
cargo run --locked -p xtask -- kat --check   # committed KAT vectors match regenerated output
cargo run --locked -p xtask -- doccheck      # documented constants + test count match code
cargo run -p xtask -- repro                  # double-build, bit-identical SHA256
```

CI (`ci.yml`) runs everything except `repro` (which is instructionally
manual so the linkage to a real release is explicit); `tamarin.yml` runs
on `model/**` changes only.

## How to modify crypto safely

1. **Trace the model first.** If you touch handshake or ratchet semantics
   in `null-crypto`, the Tamarin theories in `model/` must be updated in
   the same change, and `model/handshake.spthy` must still prove 5/5.
   The correspondence checklist is `docs/audit-scope.md` §5.
2. **Keep constants in `null-core`.** Rekey intervals, frame geometry,
   shaping, and limits all live there; `cargo xtask doccheck` enforces
   that the docs quote them. Change the constant, then update docs to
   match — never the reverse.
3. **KATs are load-bearing.** `cargo xtask kat --check` compares
   byte-for-byte with `vectors/`. Changing a KDF label, a domain separator,
   or a wire layout invalidates vectors — regenerate, *inspect the diff*,
   and commit both sides together.
4. **Fuzz everything decodable.** Every new/edited wire type must be added
   to the `xtask fuzz` corpus (`xtask/src/main.rs`) so CI exercises it.
5. **Never weaken a proven lemma.** If a change makes `root_secrecy`,
   `kci_initiator`, or `mutual_agreement` harder to prove or falsifies it,
   stop and re-design; that is a protocol regression, not a model problem.

## Testing tiers

- **Unit tests** inside crates: 91 across the workspace (`#[test]` +
  `#[tokio::test]`), enforced by `doccheck`.
- **Integration suites** in `crates/*/tests/`: TCP end-to-end
  (`e2e_tcp.rs`), deniability tripwire (`deniability.rs`), multi-device
  (`multidevice.rs`), downgrade matrix (`downgrade.rs` — 10 cases).
- **Live exercises**: `crates/null-cli` tests scripted two-process chats
  (deniable + verified-pinned) and headless TUI runs over loopback and a
  live listener.
- **Deterministic fuzz**: `cargo xtask fuzz` (stable channel, no
  cargo-fuzz/libfuzzer). See `docs/testing.md` for the full matrix.

## Dev loops

```bash
# TUI self-test demo (no daemons)
cargo run -- -p null --peer loopback --tui

# Two-process chat, line mode
cargo run --bin null -- --listen 18080            # terminal 1
NULL_DIRECT_ADDR=127.0.0.1:18080 cargo run --bin null -- \
  --peer 'null://listener?k=<base64-ek>'          # terminal 2
```

Live Tor: front the listener port with an onion service (`--control-port
9051` provisions one) and set `NULL_LIVE_TRANSPORT=1` on the dialing side;
`docs/transports.md` has the full runbook.

## Code conventions

- No `unwrap`/`expect` on security-relevant paths; errors carry context
  and, where failure changes security posture, the failure is *loud*
  (e.g., `secure_exit()` on transparency or key-mismatch).
- `zeroize` on drop for every key container; secret buffers prefer the
  stack when small.
- Every `unsafe` block (15 sites, all in `null-memory`) is documented
  per-site with its soundness argument.
- Doc-comment every public item that the formal models abstract; the
  comment should name the correspondence (e.g., `advance_chain ⇔
  h(<chain,'chain'>)`).

## Debugging the proof toolchain

- Tamarin env (pinned): `PATH=/tmp/maude351:$PATH MAUDE_LIB=/tmp/maude351
  /tmp/tamarin/tamarin-prover --prove model/handshake.spthy`.
- Proving one lemma: `--prove=mutual_agreement model/handshake.spthy`.
- Bisecting a divergent ratchet proof: `--heuristic=O`, `--derive`, and
  the oracle/sources flags documented in `model/ratchet.spthy`'s header;
  the static/shared-chain variants prove in seconds, so start from them.