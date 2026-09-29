# Release process

How a release is made, verified, and distributed so that "this binary is
what the source says" is mechanically checkable. Complement:
`docs/updates.md` (signature scheme + manifest), `docs/operations.md`
(deployment).

## 1. Gate checklist (all must pass on the tagged commit)

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --workspace --locked
cargo run --locked -p xtask -- fuzz           # 20k+ iterations
cargo run --locked -p xtask -- kat --check
cargo run --locked -p xtask -- doccheck
cargo run -p xtask -- prover --check          # pinned Tamarin/Maude install intact
cargo deny check advisories licenses bans sources   # deny.toml, fail-closed
cargo audit                                   # RustSec: 0 vulnerabilities
cargo run -p xtask -- repro                    # bit-identical double build
```

`prover --check` matters only if you intend to re-run or extend the
symbolic proofs; it verifies the sha256-pinned Maude + tamarin-prover
install (`model/prover-install.sh`) instead of trusting whatever happens
to be on `PATH`. The two supply-chain gates are fail-closed: a
known-vulnerable crate, a license outside the allow-list, an unexpected
source, or a duplicate is a release blocker, not a warning to triage
later. CI (`ci.yml`) enforces the code gates and `supply-chain.yml`
enforces the last two on a weekly + manifest-change schedule; `repro` is
run manually at release time so the double-build linkage to the actual
tagged commit is explicit. Tamarin (`tamarin.yml`) re-proves the
handshake models if `model/**` changed in the release window.

## 2. Reproducibility ceremony

`xtask repro` builds `--bin null` twice into isolated
`CARGO_TARGET_DIR`s with:

```
SOURCE_DATE_EPOCH=0  TZ=UTC  LC_ALL=C  cargo build --locked --bin null
```

and compares SHA256. For a *release* artifact, go further:

- Build in a **clean container** with the pinned toolchain
  (`rust-version = 1.75` minimum; record the exact stable version).
- Record the triple `(source commit, Cargo.lock digest, binary SHA256)` —
  this exact triple is what the update manifest binds
  (`docs/updates.md`).

## 3. Signing ceremony (offline, split keys)

1. Freeze the binary + `Cargo.lock` on air-gapped media.
2. Compute `binary_sha3_256` and `lockfile_digest` (`SHA3-256`).
3. Pick the new monotonic `version` (must be `> current_version`).
4. Build `signing_bytes = "{version}:{binary_sha3_256}"`.
5. Sign with **both** keys: Ed25519 and SLH-DSA-SHA2-128s (offline
   release key + SLH seed under the same custody).
6. Assemble `UpdateManifest`; verify it with a *throwaway* copy of the
   public keys before it ships.
7. Distribute the manifest + binary. Clients verify: downgrade floor →
   Ed25519 → SLH-DSA → binary hash → update.

Never ship a manifest whose `cargo_lock_digest_hex` doesn't match the
closure you actually built against. This is the supply-chain audit trail:
`version` says *when*, the lockfile digest says *what dependencies*.

## 4. Artifact attestation (targets)

The **shipped** story is: reproducible build + hybrid-signed manifest.
Release-process targets still on the roadmap (`docs/security-posture.md`):

- **SBOM** — emit the dependency closure (a `cargo metadata` dump or
  syft) alongside the artifact.
- **sigstore/cosign attestation** — a transparency-recorded signature on
  the release artifact itself, linking the OCI-style digest to a keyless
  identity, publishing the double-build hashes for independent
  verification.
- **Onion distribution channel** — a static `.onion` host serving
  manifest + binary, so even the *transport* of updates is anonymous
  (`docs/updates.md` §6).

These do not change the verification model (clients still require hybrid
signatures); they raise the *auditability* of the release process.

## 5. Versioning and tagging

- Format: `v2.0.0`-style tags on `main`, matching `workspace.package.version`
  (`2.0.0`). Monotonic manifest `version` advances with every shipment,
  not every tag.
- `CHANGELOG.md` is updated in the same commit as the tag; removed
  features are listed with their migration note.
- Security-fix releases follow `SECURITY.md`'s 90-day coordinated
  disclosure while still shipping to affected users first.

## 6. Post-release checks

- `cargo xtask kat --check` re-run in a fresh checkout (best-effort): the
  committed vectors must still match — a release whose vectors changed is
  a red flag, not a happy accident.
- Verify the manifest's `cargo_lock_digest_hex` against the released
  lockfile size/version bump.
- Announce the release with the fingerprint of the release verification
  key, so operators have a second channel to confirm the manifest's keys.