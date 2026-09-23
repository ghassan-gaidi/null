# API reference & rustdoc

How to read and generate the API documentation for the workspace. The
source of truth is the `//!` crate docs and pub-item comments; this page
maps the surface so you know where to look, plus the `cargo doc` recipe.

## 1. Generating documentation

```bash
cargo doc --workspace --no-deps          # public API only
cargo doc --workspace --no-deps --document-private-items   # incl. internals
```

Host the output (`.rustup`/`target/doc/index.html`) on your intranet or
CI artifact upload if you need a browsable copy; there is no doc site
dependency. Doc comments double as the model↔code correspondence notes:
every public item in `null-crypto` names the Tamarin term it maps to
(e.g., `advance_chain ⇔ h(<chain,'chain'>)`).

## 2. Crate surface, quickly

### `null-core` — shared truth
- Constants: `PROTOCOL_VERSION`, `FRAME_SIZE`, `FRAME_HEADER_SIZE`,
  `MAX_PAYLOAD_SIZE`, `TAG_SIZE`, `KYBER_REKEY_INTERVAL_MSGS`,
  `KYBER_REKEY_INTERVAL_SECS`, `SHAPER_BASE_INTERVAL_MS`, `SHAPER_BURST`,
  `CLIPBOARD_CLEAR_SECS`, `DEAD_MAN_SWITCH_SECS`, `MAX_GROUP_MEMBERS`.
- Types: `NullError` (incl. structured `MissedRekey`, `PeerBehind`,
  `Downgrade`), `Result<T>`, `FrameType`, `TransportKind`,
  `ConnectionString` (parse/`to_uri`).

### `null-crypto` — the security core
- `EphemeralKey` (X25519, rejecting DH), `KyberKeypair` (ML-KEM-1024),
  `kyber_encap_to`, `initial_root_key`.
- Handshake: `HandshakeInit`/`HandshakeResponse` (+`encode`/`decode`/
  `signing_msg`), `HandshakeInitiator` (`initiate[_verified]`,
  `finalize[_verified]`), `respond[_verified]`.
- Session: `Session` (`encrypt`, `decrypt`, `kyber_rekey_*`,
  `needs_kyber_rekey`, `rekey_events_since`, counters), `EncryptedMessage`
  (`encode`/`decode`), constants `MAX_SKIP`, `RETAINED_REKEYS`.
- `pub mod identity`: `IdentityKey`, ML-DSA-65 sign/verify, fingerprints.

### `null-frame`
- `Frame` (`new`, `dummy`, `encode`, `decode` — strictly 2048 bytes),
  `TrafficShaper` (`try_consume`, `next_delay`).

### `null-session`
- `ad_for`, `ad_for_bytes`, `pack_handshake_init/response`,
  `HandshakeReassembler`, `HandshakeMsg`, `pack_data`, `PackGoodbye`,
  `fanout_pack`/`Fanout`, `pack_rekey_request`, `unpack_frame`, `Inbox`
  (`receive`), `InboxOut`, tags (`HS_INIT_TAG`, `HS_RESPONSE_TAG`,
  `GOODBYE_TAG`, `REKEY_REQUEST_TAG`), bounds (`MAX_PENDING`,
  `MAX_REKEY_ROUNDS`, `HS_FRAG_MAX`).

### `null-transport`
- `TransportConn` (blob framing, `new_live`, `send_blob`, `recv_blob`),
  `Endpoint`, `Multiplexer` (`new`, `elect`, `dial`, `dial_live`,
  `provision_onion`, `latencies`), per-transport structs, `loopback_pair`,
  `live` (SOCKS5/SAMv3/Tor-control/`ensure_pt`/`torrc_bridge_lines`).

### `null-memory`
- `HsmBackend` trait, `SoftwareHsm`, `HardwareHsmProbe`,
  `panic_wipe_all_and_clear_screen`, `sleep_protection_status`,
  pool/advisory machinery for mlock/MADV_DONTDUMP.

### `null-identity`
- `safety_number`, `safety_number_qr_ascii`, `device_member_id`,
  `DeviceInfo`, `DeviceSet`, `TransparencyLeaf`, `TransparencyLog`.

### `null-group`
- `Group` (`create`, `add`, `remove`, `update`, `process_commit`, `join`,
  `message_key`), `TreeCommit`, `WelcomePkg`, `KeyPackage`, tree helpers
  (`tree.rs`).

### `null-update`
- `pub mod slh` (SLH-DSA-SHA2-128s), `UpdateManifest`, `UpdateStore`,
  `sign_manifest`, gossip `merge_gossip`/`gossip_message`.

### `null-tui`
- `App` (`new`, `render`, `handle_key`, `push_message`, `set_safety`,
  `poll_auto_lock`, lock/unlock), `AppAction`, `clipboard_copy_and_schedule_clear`,
  `layout_hint`.

### `null-cli`
- Binary entry point only: `main`, `Args`, chat loops, `secure_exit`,
  `graceful_quit`/`drain_inbound`, USBGuard, signal wipe, `secure_input`
  module.

### `xtask`
- Subcommands: `repro`, `fuzz [iters] [seed]`, `kat [--check]`,
  `doccheck`.

## 3. Cross-links

| Term | Where documented |
|---|---|
| Wire layout of frames/messages | `docs/wire-protocol.md` |
| KDF labels & ratchet equations | `docs/crypto.md` (mirrors the models) |
| Government of the constants | `docs/development.md` §"modify crypto safely" |
| Audit priority order | `docs/audit-scope.md` |
| Rustdoc hosting | this page; CI may `cargo doc` on demand |