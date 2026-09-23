# Cryptography — Null Triple Ratchet (NTR)

This is the plain-spoken cryptographic specification of `crates/null-crypto`.
It mirrors the Tamarin models (`model/`) and the unit tests that pin the
correspondence. Every label, parameter, and equation below is the actual
string or constant used by the code.

## 1. Primitives

| Use | Algorithm | Notes |
|---|---|---|
| Key agreement (classical) | X25519 (RFC 7748) | `x25519-dalek`, static-secret mode |
| Key agreement (post-quantum) | ML-KEM-1024 (Kyber-1024, FIPS 203) | ek 1568 B, ct 1568 B, shared secret 32 B |
| Symmetric ratchet, KDF | HKDF-SHA384 (RFC 5869) | salt always `0³⁴⁸`, output 48 B except message-key |
| Message AEAD | ChaCha20-Poly1305 (RFC 8439) | 256-bit key, 12-byte nonce, 16-byte tag |
| Identity signatures | ML-DSA-65 (FIPS 204), deterministic | vk 1952 B, sig 3309 B, context `"Null-v2.0-handshake"` |
| Hashing | SHA3-256 | fingerprints, transparency leaves/nodes, manifest digests |
| Release signatures | Ed25519 + SLH-DSA-SHA2-128s (FIPS 205) | both mandatory; `null-update`, not `null-crypto` |
| RNG | `OsRng` every session | deterministic RNGs exist only for KATs and tree node keys |

Host functions from `null-core`: `PROTOCOL_VERSION = 0x0002`,
`FRAME_SIZE = 2048`, `FRAME_HEADER_SIZE = 32`, `MAX_PAYLOAD_SIZE = 1984`,
`TAG_SIZE = 16`, `KYBER_REKEY_INTERVAL_MSGS = 50`,
`KYBER_REKEY_INTERVAL_SECS = 604800`.

## 2. Handshake (establishment)

### 2.1 Deniable mode (default)

| Step | Operation |
|---|---|
| A | `EK_A = X25519.generate()`; `(ct, k_kyber) = ML-KEM-1024 encapsulate(ek_B)` |
| A→B | `HandshakeInit = EK_A.pub ‖ ek_A ‖ ct ‖ device_id` (no identity fields) |
| B | `k_kyber = decapsulate(ct)`; `EK_B = X25519.generate()` |
| B→A | `HandshakeResponse = EK_B.pub ‖ ek_B ‖ device_id` (echo of advertised ek) |
| both | `shared = X25519(EK.priv, peer.EK.pub)` — a single ECDH (the "DH3" of 3DH; long-term-key DH1/DH2 are omitted for deniability) |
| both | `root = HKDF-SHA384(ikm = shared ‖ k_kyber, salt = 0³⁴⁸, info = "Null-v2.0-initial-root-key")` → 48 B |

This is exactly what `model/handshake.spthy` proves under Dolev-Yao:
`root_secrecy` (neither side's KEM key, nor the root, is derivable without
compromise of a party) and, in verified mode, `mutual_agreement`.

### 2.2 Verified mode (`--verified`)

Adds, on both sides: `identity_vk = ML-DSA-65 verifying key`, `signature =
ML-DSA-65 sign(signing_msg)`.

- `HandshakeInit::signing_msg()` covers `eph ‖ ct ‖ ek ‖ vk? ‖ device_id`.
- `HandshakeResponse::signing_msg(init_eph, init_ct)` covers
  `init_eph ‖ resp_eph ‖ init_ct ‖ vk? ‖ resp_ek ‖ device_id ‖ vk_echo?` —
  note it includes the responder's *current* long-term Kyber ek, so a stale
  `null://` directory key fails at finalize instead of producing a session.
- **Unknown-key-share guard**: the responder must echo the initiator's
  exact vk (`vk_echo`); `finalize_verified` aborts on mismatch. This is
  what makes `mutual_agreement` hold in the model.
- **Pinning**: `i=<ml-dsa:fingerprint>` in `null://` + `expected_fp`
  compares `fingerprint = "ml-dsa:" ‖ hex(sha3_256(vk))`. TOFU
  (`expected_fp = None`) accepts any vk and yields **no agreement claim**.
- `device_id` (16 B, derived `SHA3-256(seed ‖ "Null-v2.0-device:" ‖
  slot)[..16]`) is bound into both transcripts for multi-device safety.

### 2.3 Degenerate-input rejection

`EphemeralKey::diffie_hellman` returns `Result` and rejects, in order:

1. `peer == basepoint_bytes` (a basepoint peer would make DH output equal
   our own public key — surfaced by the `root_secrecy` model),
2. non-curve points (`to_edwards` `None`),
3. small-order (twist) points,
4. all-zero DH outputs.

Every rejection is a loud `NullError::Crypto`, not a silent fallback.

## 3. Session state and the three ratchets

`Session` holds: `send_counter`, `recv_counter`, `msgs_since_kyber`,
`root_key [u8;48]`, `chain_key [u8;48]`, `ecdh_ratchet` (live X25519
ephemeral), `peer_ecdh_pub`, `kyber_longterm` + `peer_kyber_ek`,
`kyber_generation`, `retained_rekeys` (≤ 8), and `skipped` (chain-key cache
bounded by `MAX_SKIP = 200`, wiped on drop).

### 3.1 Symmetric chain

- Init: `chain = HKDF(root, 0³⁴⁸, "Null-v2.0-chain-init")` → 48 B.
- Step: `chain' = HKDF(chain, 0³⁴⁸, "Null-v2.0-chain-step")` → 48 B.
- Message key: `HKDF(root ‖ chain ‖ counter(8 BE) ‖ ecdh(32) ‖
  kyber_shared, 0³⁴⁸, "Null-v2.0-message-key")` → 32 B. (`counter` is the
  8-byte big-endian send or hop counter.) Keys are derived on the stack for
  `kyber_shared.len() <= 64`; larger inputs use a heap buffer — either
  path is zeroized.

### 3.2 ECDH ratchet

Fresh X25519 ephemeral per sent message, **rotate-before-send**; the
receiver derives a candidate DH from the frame's `ecdh_pub`, and only
adopts it as `peer_ecdh_pub` after the AEAD tag verifies. This keeps both
sides' `DH` equal at every counter (`model/ratchet.spthy` `executable`).

Documented limitation: a *late* frame decrypts only if the receiver has
not rotated its own ECDH secret since (per-message DH rotation), because
the receiver cannot keep every past secret.

### 3.3 Kyber (PQ) re-encapsulation

- Trigger (`needs_kyber_rekey`): `msgs_since_kyber >= 50` **or**
  `last_kyber_rekey.elapsed() >= 604800 s (7 days)`. **Both** the sender
  (`encrypt`) and the receiver (`decrypt`) count toward this — a mostly
  silent peer will still rekey on its own next send.
- Send side: emit a `KyberRekey` frame with the fresh ciphertext *first*,
  then the data frame. Receive side: `mix_kyber_shared`:
  `root' = HKDF(root ‖ k_new, 0³⁴⁸, "kyber-ratchet")` → 48 B; increments
  `kyber_generation` and retains the ciphertext+secret for replay
  (`RETAINED_REKEYS = 8`).
- Rekey ciphertexts are **unauthenticated**: injection causes *desync
  (DoS)*, never key leakage; the session fails loud (re-handshake demand)
  via the Inbox resync state machine (`docs/wire-protocol.md` §5).
- Quantum PCS: after one successful rekey, an adversary who compromised
  everything before it no longer knows the root. Classical PCS after one
  message (ECDH ratchet).

## 4. Message AEAD

- Key: per-message (above). Nonce: `n = [0u8;4] ‖ counter.to_be_bytes()`
  (12 B total).
- Associated data: opaque to `null-crypto`; the session layer supplies
  `"{sender}|{receiver}|{PROTOCOL_VERSION}"` (onion labels, `ad_for`) or
  `hex(ek_sender)|hex(ek_receiver)|{PROTOCOL_VERSION}` (long-term Kyber
  eks, `ad_for_bytes` — identical on both sides, direction-bound).
- Wire: `EncryptedMessage = counter(8 BE) ‖ kyber_generation(8 BE) ‖
  ecdh_pub(32) ‖ ciphertext` — minimum 48 B before the payload; decode
  rejects anything shorter.
- The `kyber_generation` field rides every message, so missed rekeys are
  *detected* (never silently diverged): receiver older than the message's
  generation buffers + requests a replay
  (`MissedRekey`), sender older than the receiver's
  (`PeerBehind`) is healed by pushing retained rekeys.

## 5. Out-of-order and loss behavior

- `skipped` maps `u64` counters → **chain keys** (48 B), bounded by
  `MAX_SKIP = 200` in both jump size and total entries; message keys are
  re-derived per frame from the cached chain key plus the frame's own
  `ecdh_pub`. Replays and oversized forward jumps are rejected.
- Three bounded-loss mechanisms are *deliberately distinct*: `MAX_SKIP`
  (out-of-order jumps), `RETAINED_REKEYS` (rekey replay), and the Inbox's
  `MAX_PENDING = 16` / `MAX_REKEY_ROUNDS = 3` (pending undecryptable
  buffer and resync cap). Conflating them in a review is a common error —
  `docs/audit-scope.md` calls this out.

## 6. Identity layer (`null_identity`)

- `safety_number(ik_a, ik_b, session_id) = 12×5-digit groups of
  SHA3-256(canonical(vkA,vkB) ‖ session_id)`; inputs sorted canonically so
  both sides agree.
- Key-transparency log: in-RAM append-only Merkle log of peer vk hashes
  (`observe` fails closed on change with a possible-MITM error; checkpoints
  export as `null-kt-v1:<contact>:<leaves>:<hex root>` and verify back).
- Device sets: `member_id = SHA3-256("Null-v2.0-device-member:" ‖ fp ‖
  device_id)`; `DeviceSet` tracks ek/revoked/added_epoch per device;
  unknown ids count as revoked (fail closed). See `docs/multidevice.md`.

## 7. Domain-separation reference

| Label | Used for |
|---|---|
| `Null-v2.0-initial-root-key` | handshake root KDF |
| `Null-v2.0-chain-init` / `Null-v2.0-chain-step` | symmetric chain |
| `Null-v2.0-message-key` | per-message AEAD key |
| `kyber-ratchet` | rekey root mix |
| `Null-v2.0-handshake` | ML-DSA signature context |
| `Null-v2.0-device:` / `Null-v2.0-device-member:` | device id / member id |
| `Null-v2.0-hsm-bind:` | Tier-1 device-bound local secret |
| `null-mls-node` / `null-mls-path` / `null-mls-root` | TreeKEM node/path/root KDFs |
| `null-mls-welcome-wrap` | join welcome sealing |

Changing a label is a protocol change: regenerate KATs, re-run the
prover, update this table.

## 8. What is and is not claimed

Proven (Tamarin, CI-enforced): establishment secrecy, initiator KCI
resistance, verified-PINNED mutual agreement, honest-run executability —
all under Dolev-Yao with compromise.

In progress: ratchet message secrecy, forward secrecy, and PQ-PCS after
rekey (`model/ratchet.spthy`; tests + KATs today).

Not claimed: deniable-responder KCI (false by construction — anyone can
encapsulate to B and compute the root), formal observational-equivalence
deniability, side-channel resistance (`dudect` not run), and post-quantum
security of the *classical* ECDH component itself (the 50-message/7-day
Kyber rekey cadence is what bounds Harvest-now-decrypt-later exposure).

## 9. Files

- Implementation: `crates/null-crypto/src/lib.rs` (1572 lines, 14 tests).
- Models: `model/handshake.spthy` (5/5 proven), `model/ratchet.spthy`
  (modelled, proofs in progress).
- Vectors: `vectors/{x25519,kdf,kyber,mldsa,handshake,frame}.json`.
- Anomaly notes for reviewers: `docs/audit-scope.md` §4.