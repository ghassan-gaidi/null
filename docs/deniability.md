# Deniability analysis (OTR-style participant repudiation)

## What deniable mode guarantees

In default (deniable) mode, a Null session produces **no transferable
cryptographic proof** that a particular party participated:

1. The handshake is Triple-DH + Kyber KEM with **no signatures**. Either
   peer could have forged every byte unilaterally: ephemeral X25519 keys
   are fresh per session, and the Kyber encapsulation is computable by
   anyone holding the responder's *public* key.
2. Message authentication (ChaCha20-Poly1305 tags) uses **symmetric keys
   derived from shared secrets**. Both parties can forge valid-looking
   transcripts after the fact, so a transcript convinces no third party
   (standard symmetric-deniability argument, as in OTR/Signal).
3. No long-term identity material appears on the wire at all: the
   `identity_vk` and `signature` handshake fields are `None`, verified
   code paths are never entered, and nothing links one session to the next
   (fresh ephemerals every session — see unlinkability check below).

## What it does NOT guarantee

- **Not anonymity against a global observer.** Deniability is about
  *repudiation to a judge*, not *hiding from a watcher*. Metadata
  protection is Tor's job in this system (transport layer), not the
  cryptographic deniability property.
- **Not protection against the peer.** Your peer receives plaintext; no
  cryptography prevents screenshots, logging, or testimony. Deniability
  defeats *forgery-proof*, not *witnesses*.
- **Not post-quantum deniability in the strong academic sense.** The
  classical argument above holds against quantum adversaries for the
  symmetric-MAC part; formal PQ-deniability models are an open research
  area and are NOT claimed here.
- **Verified mode voids all of this by design.** `--verified` attaches
  ML-DSA signatures precisely so participation *is* provable to anyone
  holding the transcript plus the verification key. Never mix modes
  within one contact if repudiation matters.

## Enforcement

`crates/null-session/tests/deniability.rs` is a tripwire, not just a
test: it completes full deniable sessions, captures every transmitted
byte, and asserts (a) decoded handshake messages carry no vk/signature,
(b) deniable transcripts are smaller than verified ones by at least the
vk+signature size (no hidden identity blobs), and (c) two sessions between
the same parties share zero handshake bytes (freshness/unlinkability).
Any future change that leaks identity material into deniable mode fails
the build.
