# Known-answer vectors

Deterministic cryptographic outputs, committed so independent
implementations can cross-check us and drift fails loudly
(`cargo xtask kat --check`, wired into CI).

## Files

| File | Contents | Deterministic? |
|---|---|---|
| `x25519.json` | Fixed secrets → publics + shared secret | Yes, fully |
| `kdf.json` | `initial_root_key` output, fingerprint, safety number, transparency checkpoint/root | Yes, fully |
| `kyber.json` | Deterministic ML-KEM-1024 ek from fixed seed | ek yes; encap sample is a verified roundtrip, not a KAT (randomized by design) |
| `mldsa.json` | Fixed-seed ML-DSA-65 vk, fingerprints, device ids, deterministic signatures | Yes, fully |
| `handshake.json` | Fixed-field init/response with REAL signatures + wire encodings | Yes, fully |
| `frame.json` | Decode-direction vectors (valid + bad-version) | Yes (`encode()` pads randomly by design, so encode outputs are not vectored) |

## Independent cross-checks performed (2026-09-10)

- **X25519**: public derivation + DH shared secret both directions
  reproduced with OpenSSL 3.0.13 (`openssl pkey` / `pkeyutl derive`).
- **HKDF-SHA384 root**: reproduced with a from-scratch Python
  implementation of the RFC 5869 extract-and-expand formula with SHA-384
  (`salt = 0^48`, `info = "Null-v2.0-initial-root-key"`, L=48).
- ML-KEM / ML-DSA internals rely on their crates' own audited test suites
  plus our deterministic roundtrips; no second implementation was
  available in this environment (noted honestly — a Wycheproof-style
  cross-check remains future work).

## Regenerating

```bash
cargo run -p xtask -- kat            # rewrite vectors/*.json
cargo run -p xtask -- kat --check    # verify committed files match
```

Any change to cryptographic outputs shows up as a diff here first —
treat unexpected diffs as guilty until proven innocent.
