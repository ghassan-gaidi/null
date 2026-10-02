# Updates & supply chain

> Status: CLI live — `null update check` verifies an operator-fetched
> manifest+binary pair (zero writes); `null update apply --to PATH`
> installs the verified binary via temp-file + atomic rename (explicit
> opt-in). Onion-fetch distribution remains a documented follow-up (§5).

How release updates are signed, verified, distributed, and defended
against downgrade. Implementation: `crates/null-update` (312 lines).

## 1. Threat model for updates

The distributor is on the adversary's target list: a stale or forged
binary is a full endpoint compromise. Null's answer is **two independent
signature schemes, both mandatory**, a **monotonic version floor**, and a
**recorded `Cargo.lock` digest** so what you run is what was built.

## 2. Hybrid signatures (both must verify)

- **Ed25519** (classical) **and SLH-DSA-SHA2-128s** (FIPS 205,
  post-quantum) sign the same bytes. `UpdateManifest::verify` runs the
  downgrade check first, then Ed25519, then SLH-DSA; either failure
  rejects the whole offer.
- SLH-DSA keys are derived from a 48-byte OS seed:
  `slh_keygen_internal(&seed[..16], &seed[16..32], &seed[32..])`
  (N=16, deterministic keygen); the verification key is 32 B.
  (This is the FIPS 205 name; older literature calls the family SPHINCS+.)

## 3. Manifest format

```
version: u64                 # monotonic, 64-bit
sha3_256_hex: String         # SHA3-256 of the release binary
ed25519_sig_hex: String      # over signing_bytes()
sphincs_sig_hex: String      # same bytes, SLH-DSA
cargo_lock_digest_hex: String  # SHA3-256 of Cargo.lock
```

- `signing_bytes() = "{version}:{sha3_256_hex}"` — the only bytes signed.
- Manifests are capped at 1 MiB at parse.
- `sign_manifest` computes the binary digest, both signatures, and the
  lockfile digest in one step (the offline signing ceremony helper).

## 4. Verification order and the downgrade floor

`UpdateStore` holds the release verification keys + `current_version`:

1. `version < min_version` → `NullError::Downgrade` — a stale manifest is
   rejected *before* any expensive signature work.
2. Ed25519 verify (must be exactly 64 bytes).
3. SLH-DSA verify.
4. `sha3_256_hex(offered_binary) == manifest.sha3_256_hex`.
5. Keep only strictly-newer, fully-verified offers (`needs_update()`).

An offer can arrive from anywhere and be malformed, invalid, or hostile —
it is rejected without touching state. **Trust comes from signatures,
never from the transport that delivered them.**

## 5. P2P gossip distribution

- `gossip_message()`: `manifest_bytes ‖ 0x00 ‖ binary`.
- `merge_gossip()` splits on the first `0x00` byte, verifies, and adopts
  the newest-verified offer. Malformed/violating payloads are dropped
  without mutation.
- Connected peers can therefore propagate updates to each other with zero
  infrastructure (metadata rides the same anonymity network as chat).

## 6. Distribution channels

- **Shipped**: verified gossip, offline signing, downgrade defense.
- **❨target❩**: primary distribution over a static `.onion` service with
  the release key(s) pinned out-of-band, per the design spec. The verify
  path exists (a manifest signed by the release keys is accepted anywhere);
  the onion *fetch* path is an integration point, not shipped code — there
  is no HTTP/DNS-fetch code in the tree today.

## 7. Release-key management (operational)

- Release signing keys are **offline and split**: Ed25519 key and SLH-DSA
  seed kept on air-gapped media or an HSM; the manifest ceremony runs
  there, and only the signed manifest + binary leave.
- Keep the release verification keys in `UpdateStore` (or the equivalent
  in a distribution you control) where they can be rotated — the manifest
  format carries no key-rotation mechanism, so manual coordination is
  required for rotation.
- A compromised release key is catastrophic by design (the attacker can
  sign anything at or above your current version). Protect it accordingly;
  see `SECURITY.md` for the disclosure path if you ever suspect it.

## 8. Relation to the build

- `cargo xtask repro` verifies the binary is what it claims to be
  (bit-identical rebuild). The `cargo_lock_digest_hex` ties the shipped
  binary to an exact dependency tree; any lockfile change (adding a
  dependency, version bump) invalidates an older manifest's promise.
- Full release ceremony: `docs/release.md`. Supply-chain hardening targets
  (SBOM, sigstore attestation) live in `docs/security-posture.md`.