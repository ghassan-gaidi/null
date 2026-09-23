# Wire protocol specification

Byte-level description of everything that crosses a Null connection, from
the `null://` discovery string to the padded frames on the wire. The
canonical types are in `null-core` (constants) and `null-frame`
(geometry); the code is the source of truth — this document captures it so
implementations can be audited or re-implemented.

All integers are big-endian unless stated. All length fields are u16 or
u32 BE as specified. The wire protocol version is `0x0002`
(`PROTOCOL_VERSION`). Any frame with a different version is rejected at
decode — there is no in-band fallback or negotiation.

## 1. Discovery: the `null://` connection string

Grammar (parsed by `null_core::ConnectionString`):

```
null://<host>.onion?k=<base64 ML-KEM-1024 ek>&i=<ml-dsa:fingerprint>&t=tor,i2p,nym
```

- `<host>` is the 56-character Tor v3 hostname **without** the `.onion`
  suffix. The literal host `listener` is a local-test hook that dials
  `NULL_DIRECT_ADDR` instead of a SOCKS proxy and is never valid on the
  real network.
- `k=` (required): base64 (standard alphabet) of the peer's 1568-byte
  ML-KEM-1024 encapsulation key.
- `i=` (optional): the peer's ML-DSA-65 fingerprint, `ml-dsa:<hex
  sha3-256(vk)>`. Presence enables pinning in verified mode; absence means
  TOFU, which the UI announces.
- `t=` (optional): comma-separated transport priority list from
  `tor,i2p,nym,snowflake,webtunnel,obfs4`.
- Unknown query keys are ignored; a bare base64 segment (no `k=`) is
  accepted as a shorthand for `k=`.

## 2. Blob framing on the transport

Transport connections carry **length-prefixed blobs** (not raw frames):

```
blob := u32 BE length ‖ bytes          (length ≤ 16 MiB)
```

`recv_blob` enforces the cap and a 120-second receive timeout. A single
"logical unit" (a handshake fragment, a padded frame, or the multi-frame
handshake sequence) may span several blobs; each blob is one encoded 2048-byte frame or one handshake fragment.

## 3. Frame layout (fixed 2048 bytes)

```
offset  size  field
0       2     ver            = 0x0002 (any other value: reject)
2       1     type           = 0x01 Data | 0x02 Dummy | 0x03 Control | 0x04 KyberRekey
3       8     counter        u64 BE
11      4     payload_len    u32 BE, ≤ 1984 (MAX_PAYLOAD_SIZE)
15      17    reserved       randomized on encode, ignored on decode
32      …     payload        plaintext payload bytes (≤ 1984)
32+len  rest  padding        zeroed then randomized on encode; ignored on decode
```

- Decode accepts **only** exactly `2048` bytes (`FRAME_SIZE`); anything
  else is rejected.
- Header size is `32` (`FRAME_HEADER_SIZE`); `payload_len` > `1984`
  (`MAX_PAYLOAD_SIZE`) is rejected.
- The payload is *ciphertext by convention*: the session/crypto layer
  encrypts before packing, and the 16-byte Poly1305 tag (`TAG_SIZE`) lives
  inside the payload. The frame layer is agnostic.
- `Frame::dummy(counter)` builds `Dummy` frames with a random 64-byte
  payload — indistinguishable in size and shape from real traffic.

## 4. Encrypted message layout (`EncryptedMessage`)

```
counter(8 BE) ‖ kyber_generation(8 BE) ‖ ecdh_pub(32) ‖ ciphertext
```

Minimum 48 bytes before payload; decode rejects shorter inputs. `counter`
and `kyber_generation` are monotonic per session; the generation field is
what makes lost rekeys detectable (`docs/crypto.md` §4).

## 5. Handshake messages

### 5.1 Blob/flag codecs

- `put_blob/get_blob`: `u16 BE length ‖ bytes`.
- `put_sig/get_sig`: 1-byte flag (`0`/`1`) then optional blob.

### 5.2 `HandshakeInit` (A → B)

```
eph(32) ‖ ek_blob ‖ ct_blob ‖ vk_flag(1)+(blob)? ‖ sig_flag(1)+(blob)? ‖ device_id(16)
```

- `eph` X25519 public (32).
- `ek_blob`: initiator's long-term ML-KEM-1024 ek (1568 B), so the
  responder can re-encapsulate at later rekeys.
- `ct_blob`: the ML-KEM-1024 ciphertext (1568 B).
- `vk`/`sig`: present only in verified mode (vk 1952 B, sig 3309 B).
- `device_id`: 16 bytes; all-zero = unbound (single-device).
- Decode rejects: length < 32, missing vk flag, bad flag bytes, and a
  remainder ≠ 16 bytes.

### 5.3 `HandshakeResponse` (B → A)

```
eph(32) ‖ ek_blob ‖ vk_flag(1)+(blob)? ‖ sig_flag(1)+(blob)? ‖ device_id(16) ‖ echo_flag(1)+(blob)?
```

- `eph`: responder's fresh X25519 public.
- `ek_blob`: the responder's long-term ek — usually an echo of the
  advertised `k=`; verified finalize hard-fails if it differs (stale
  `null://` string).
- `sig`: over `signing_msg(init_eph, init_ct)` (see `docs/crypto.md`
  §2.2), which includes the responder's *current* ek.
- `echo` (`vk_echo`): the initiator's vk exactly as the responder saw it;
  mismatch aborts (unknown-key-share guard).
- Decode rejects trailing bytes.

### 5.4 Handshake fragmentation

1548+1568 B of Kyber material cannot fit one 1984-byte payload, so
handshake messages are fragmented across Control frames:

```
per-frame chunk := tag(1) ‖ frag_idx(1) ‖ frag_total(1) ‖ chunk_bytes
```

- `tag`: `0x01` init, `0x02` response.
- `frag_idx`/`frag_total`: 1-byte indices; max chunk size
  `HS_FRAG_MAX = 1900`.
- `HandshakeReassembler` rejects interleaved handshakes, out-of-range
  indices, and unknown tags; one handshake per direction at a time.
- A handshake message is therefore 1–2 frames (init always 2 in verified
  mode).

## 6. Control payloads

| Tag | Value | Payload | Meaning |
|---|---|---|---|
| Handshake init fragment | `0x01` | `frag_idx‖frag_total‖chunk` | ↩ §5.4 |
| Handshake response fragment | `0x02` | `frag_idx‖frag_total‖chunk` | ↩ §5.4 |
| Goodbye | `0x10` | empty | orderly shutdown; receiver prints + wipes |
| Rekey request | `0x11` | `from_gen(8 BE)` | "re-send your rekey events newer than generation G" |

Data frames are never valid in a handshake position; a handshake with a
data-frame payload is rejected (`handshake_bytes_as_data_rejected`,
`rekey_ct_as_data_rejected` in the downgrade matrix).

## 7. Direction binding (associated data)

The session layer supplies AD for every message AEAD:

- **Onion mode** (`ad_for`): `"{sender_onion}|{receiver_onion}|{version}"`
  where `version` is the decimal `2` — e.g. `alice|bob|2`.
- **EK mode** (`ad_for_bytes`, live sessions): `hex(ek_A)|hex(ek_B)|2`,
  built from the long-term Kyber eks — identical on both sides, so either
  peer computes the same bytes, but the payload cannot be replayed into a
  different session or direction.

A message key is therefore bound to: its direction (through AD), session
(through root/chain), counter, current ECDH, and current Kyber shared
secret (`docs/crypto.md` §4). The AD contains no counter — the AEAD nonce
is the per-chain counter.

## 8. Loss-recovery protocol (`Inbox`)

State machine in `null_session::Inbox` on top of `Session`:

- **`MissedRekey { have, want }`**: message carries a `kyber_generation`
  newer than ours. Buffer `(msg, ad)` (cap `MAX_PENDING = 16`, oldest
  dropped with a notice), emit a `RekeyRequest` for generation `have` via
  a Control frame, increment `request_rounds`. After `MAX_REKEY_ROUNDS
  = 3` consecutive unanswered rounds the session aborts with
  "PQ resync impossible after 3 rounds: re-handshake required" — loud
  failure, never silent divergence.
- **`PeerBehind { have, want }`**: *we* are newer. Drop the stale message
  with a notice; push retained rekeys newer than `want` outbound
  (`RETAINED_REKEYS = 8` retention) so the peer heals.
- A successful rekey resets `request_rounds` and replays the buffer.

There is no frame-level ACK; the generation counters riding on every
message are the whole loss-detection mechanism.

## 9. Version and downgrade

- Frame `ver != 0x0002` → reject at decode.
- Manifest `version < min_version` → `NullError::Downgrade` (null-update
  layer, `docs/updates.md`).
- The 10-case downgrade matrix (`crates/null-session/tests/downgrade.rs`)
  exercises exactly the attack shapes this layer is claimed to stop:
  stripped init fields, version rollback, handshake-as-data, replay,
  rekey-as-data, and a control sanity case.

## 10. Test vectors

`vectors/frame.json` pins a canonical valid frame (counter 7, payload
"hello") and a bad-version frame; `vectors/handshake.json` pins real
signed init/response wire bytes; `vectors/*.json` are regenerated and
enforced by `cargo xtask kat --check` (see `vectors/README.md`).