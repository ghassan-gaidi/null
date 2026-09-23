# Security policy

Null is a post-quantum, metadata-resistant terminal messenger. This file
describes how vulnerabilities are reported, triaged, and disclosed, and what
attack surface is in scope.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**
Use the private channel instead:

- **Email:** `security@ghassan-gaidi.dev` — PGP preferred; the fingerprint is
  published on the maintainer's profile and in release artifacts.
- **GitHub private advisory:** use the "Report a vulnerability" button on the
  repository (`https://github.com/ghassan-gaidi/null/security/advisories/new`).

Included in every report, if available:

1. Project + version (commit hash or release tag) affected.
2. Affected component (crate, module, or model file — see
   `docs/audit-scope.md` for the review order).
3. Type of issue (memory safety, cryptographic, protocol, DoS, side channel…).
4. Steps to reproduce, including any attacker capabilities assumed.
5. Impact estimate: what an attacker gains, and under which adversary model.

## Handling and disclosure timeline

We follow a **90-day coordinated-disclosure** policy, with a 7-day
provisional acknowledgment:

| Day | Action |
|---|---|
| 0 | Reporter files the report; maintainer acknowledges within 7 days |
| 1–21 | Triage + repro; a fix is prepared and tested against all CI gates |
| 30 | Backport if release branches exist; advisory drafted |
| 90 (default) | Public disclosure after the fix ships; CVE requested where applicable |

The clock may be shortened or extended by mutual agreement (e.g., an active
0-day exploitation wave, or a complex fix that needs a second formal-proof
pass). Reports that are only about a *theoretical* property of the formal
models are welcome and get the same process.

## Scope

### In scope

- `crates/null-crypto` — handshake, ratchet, KEM/AEAD logic, identity.
- `crates/null-session` — framing pipeline, inbox recovery, resync state.
- `crates/null-group` — TreeKEM commits/welcomes/removal.
- `crates/null-frame`, `crates/null-core`, `crates/null-identity`.
- `crates/null-memory` — the `unsafe` wipe/mlock surface (15 sites).
- `crates/null-update` — hybrid signature verification, downgrade floor.
- `crates/null-transport` — live daemon dialing, sidecar handling.
- `crates/null-cli`, `crates/null-tui` — only where they touch key material
  or loss/wipe behavior (a TUI rendering glitch is a normal bug, not a
  security finding).
- `model/*.spthy` — flaws in the Tamarin models (abstraction mismatch or an
  unproven lemma), even when no Rust code is wrong yet.
- Build/release supply chain — anything that breaks the reproducible-build
  or signature guarantees in `docs/release.md`.

### Out of scope (non-findings)

- Endpoint compromise at root/kernel level (documented in
  `docs/threat-model.md` as out of scope for any messenger).
- Live-process memory scraping by the peer or by user-level malware that is
  already running; mitigations are documented, not guarantees.
- Anonymity against a global passive adversary beyond what the transport
  layer provides (Tor/I2P/Nym).
- Physical coercion ("rubber-hose"): duress/decoy behavior is mitigation,
  not a proof against torture.
- Known, documented limitations listed in `docs/security-posture.md` and
  `README.md` (e.g., ratchet proofs in progress, `dudect` not run, no
  sanitizer fuzzing).

## Verification of fixes

Every fix must pass the full gate set before it is shipped:

```
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --workspace --locked
cargo run -p xtask -- fuzz
cargo run -p xtask -- kat --check
cargo run -p xtask -- doccheck
cargo run -p xtask -- repro
```

Tamarin model changes additionally run `.github/workflows/tamarin.yml`
(handshake: 5/5 lemmas must stay verified; ratchet/legacy: parse-check). A
fix that weakens a proven lemma, a KAT vector, or a documented claim is
not merged.

## Reporting honor roll

The `README.md` section "Security" will list credited reporters with their
permission. Null is free software; report freely, responsibly, and without
holding back details.