# Threat model

## Actors

| Actor | Capability | In scope |
|---|---|---|
| Network observer (global, passive) | Traffic analysis, timing, harvest-now-decrypt-later storage | Yes — metadata defenses + PQ crypto |
| Network attacker (active) | MitM, injection, replay, dropping, rushing | Yes — AEAD, transcripts, resync bounds |
| Past/future self (device seizure) | Disk imaging, memory dumps (live or cold) | Partial — RAM-only + wipe; cold-boot with power retained is NOT defeated, only made expensive |
| Coercive actor | Demands keys/messages, physical access | Partial — duress wipe, decoy mode, deniability; no crypto resists rubber-hose against *future* messages |
| Malicious group member | Reads group traffic, sends malicious commits | Yes — TreeKEM PCS, fork/gap rejection |
| Malicious update distributor | Serves crafted manifests/binaries | Yes — hybrid signatures + downgrade floor |
| Endpoint malware (user level) | Keylogging, screen capture, memory scrape of live process | Partial — evdev input, clipboard hygiene, anti-dump; a live-process scraper wins, stated plainly |
| Endpoint malware (root/kernel) | Everything | **No** — out of scope for any messenger |
| Quantum computer (future) | Breaks X25519/Ed25519/ML-DSA-65? No — breaks classical only | Yes for classical algs (Kyber/SLH cover); ML-DSA-65 + SLH-DSA are believed quantum-resistant |

## Trust assumptions (explicit)

1. The Rust toolchain, crates.io registry, and pinned dependency tree are
   honest (mitigated by `Cargo.lock` + reproducible builds, not eliminated).
2. The OS kernel enforces `mlock`/`ptrace` scope correctly.
3. The Tor/I2P/Nym daemons the transports dial are the genuine articles
   (sidecar integrity is the operator's job; traffic remains E2E-encrypted
   regardless).
4. The user verifies safety numbers / fingerprints out-of-band at least
   once (TOFU otherwise — the UI says so every time).
5. Randomness (`OsRng`) is sound.

## Non-goals (will not fix, by design)

- Anonymity against a global passive adversary beyond what Tor provides.
- Protection of plaintext from the peer (screenshots, testimony).
- Forward secrecy against an adversary who continuously exfiltrates live
  session state (ratchets heal point compromises, not permanent implants).
- Hiding the *fact* that Null is running (no steganography of the binary).
- Post-quantum deniability in the academic observational-equivalence
  sense (classical deniability argument documented in
  `docs/deniability.md`).

## Per-component notes

- **Handshake**: 3DH-core gives deniability; Kyber-KEM gives quantum
  secrecy of establishment. Verified mode trades deniability for mutual
  authentication deliberately and loudly.
- **Ratchet**: one-way chains (FS), per-message ECDH (classical PCS),
  periodic Kyber re-encap (quantum PCS). Generation counters + bounded
  resync convert loss into loud failure, never silent divergence.
- **Groups**: TreeKEM with blank nodes; removal heals forward; forks/gaps
  rejected. A malicious committer can always deny service (withhold
  commits) — availability from a malicious insider is not claimed.
- **Transport**: metadata minimization only; all security properties hold
  even over a fully adversarial channel (proved in the Tamarin model,
  which assumes Dolev-Yao network).
- **Updates**: TOFU on first release key; after that, monotonic + hybrid
  signed. A compromised release key is catastrophic by design — protect
  it accordingly (offline, split).
