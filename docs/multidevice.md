# Multi-device design

One identity (ML-DSA-65 key), N device sub-keys (Kyber + X25519 each).

## Model

- Each device holds the shared identity seed (or its own — deployment
  choice) and generates a stable device id via
  `IdentityKey::device_id(slot)`: `SHA3-256(seed ‖ tag ‖ slot)[..16]`.
  Same identity + same slot always yields the same id, so devices keep
  their identity across restarts with **zero disk writes**.
- Device ids ride in verified handshakes (`device_id` field, handshake
  encoding v2) and are covered by the ML-DSA transcript signatures on
  both sides. Swapping a device id post-signing invalidates the
  signature — sessions cannot be silently re-bound across a user's
  devices (tested: `device_confusion_rejected`).
- Deniable handshakes carry zeros (unbound), preserving prior behavior.

## 1:1 chats

The sender keeps one ratchet `Session` per peer device and fans out with
`fanout_pack` (one entry per active device, each with its own ek-bound
AD). Receiving is per-session as usual; duplicate delivery across a
user's own devices is the application's concern (same plaintext, distinct
sessions — no cross-decryption possible by construction).

## Groups

Each device joins as its own member with
`member_id = device_member_id(identity_fp, device_id)` — deterministic
per (identity, device), so all peers derive the same member id without
extra exchange. Revoking a device is exactly `Group::remove(member_id)`:
a TreeKEM removal commit with true PCS (the removed device cannot read
future epochs). The `DeviceSet` roster (`active_devices`) is the fan-out
set; revoked/unknown ids fail closed and are never messaged.

## Limits (stated plainly)

- Device enrollment itself is out-of-band (scan a QR, compare safety
  numbers per device). There is no server-side device directory — that is
  the point — so loss of all devices means loss of the identity seed.
- A compromised device sees group plaintext from its own epochs (standard
  MLS semantics); revocation heals forward only.
- Sender-key style group fan-out (one encryption per group) is NOT
  implemented; fan-out is per-recipient-session (bandwidth cost O(n),
  chunked by the 2048B frame layer like everything else).
