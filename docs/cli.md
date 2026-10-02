# CLI deep behavior

The flag reference lives in `README.md` (it is the quick-start surface).
This page documents **behavior beyond the flag list**: modes, environment
switches, lifecycle, exit codes, and the security edge cases the reference
doesn't explain.

## 1. Modes of operation

| Mode | Trigger | What runs |
|---|---|---|
| Idle park | no `--peer`, no `--listen` | Transports ready, prints hints, waits for Ctrl-C → wipe |
| Loopback demo | `--peer loopback` | Self-contained E2E: handshake → ratchet → frames → shaper → decrypt; interactive self-chat REPL |
| Line chat | `--peer <null://…>` (no `--tui`) | `chat_loop`: shaped sends, `Inbox` recovery, `[peer]` echo lines |
| TUI chat | any session + `--tui` | `chat_loop_tui` / `tui_loopback`: full-screen Ratatui |
| Responder | `--listen <PORT>` | Binds `127.0.0.1:<PORT>`, prints its `null://` string, serves **one** inbound handshake, then chats |

Idle mode is a real milestone boundary: transport + lifecycle are live
(wipe-on-signal, probes) but no session runs; the README says so and this
doc keeps it honest.

## 2. The responder's `null://` string

`--listen` prints the string with:

- **onion host**: provisioned ephemeral onion from `--control-port` (Tor
  `ADD_ONION`, then the 56-char host), or the literal `listener` when no
  control port is given (a local-test host that dials `NULL_DIRECT_ADDR`;
  never valid on the real network).
- **`k=`**: base64 of the listener's long-term ML-KEM-1024 ek.
- **`i=`**: the listener's ML-DSA-65 fingerprint *when running
  `--verified`* (absent otherwise — and the initiator should refuse to
  trust a verified session that lacks `i=` pinning).
- **`t=`**: the transport priority from `--transports`.

## 3. Environment switches

| Variable | Effect |
|---|---|
| `NULL_LIVE_TRANSPORT=1` | Force real daemon dialing; absent daemons become hard errors instead of virtual stubs. Any real anonymity use **requires** this on the dialing side |
| `NULL_DIRECT_ADDR=host:port` | For `listener`-host strings only: raw TCP dial of a local test listener |

## 4. Verified-mode runtime behavior

When `--verified`:

1. The initiator decodes the peer's `k=`, deriving `ad_for_bytes` from the
   session's ek and the peer's ek (identical on both sides).
2. An ephemeral `IdentityKey` is minted, its fingerprint is the `i=`
   annotation, and the handshake carries ML-DSA-65 signatures.
3. On finalize: `finalize_verified` checks the responder echoed **our
   exact vk** (unknown-key-share guard) and returned the **advertised
   Kyber key** (stale-string guard); any mismatch → error + `secure_exit`.
4. If `i=` was provided in `--peer`, it pins the peer's fingerprint; if
   not, the CLI prints **"TOFU: no i= fingerprint in peer string!"** — an
   honest, loud statement that this is not authenticated.
5. A safety number + scannable QR are printed; both sides must agree
   out-of-band.
6. The peer's attested vk is recorded in an in-RAM transparency log; a
   changed key for the same contact fails closed ("possible MITM") and
   triggers a wipe.

## 5. Deniable vs verified — mixing

- `--deniable` is the default (`default_value_t = true`); `--verified`
  upgrades. They are mutually exclusive in intent: verified mode attaches
  signatures precisely so participation is *provable*, which voids
  deniability. Flags are not the only guard — a `--verified` initiator
  against a deniable responder aborts at finalize (the responder sent no
  vk/signature).
- The 10-case downgrade matrix (`crates/null-session/tests/downgrade.rs`)
  exercises stripped-init, stripped-signature, stripped-vk, version
  rollback, handshake-as-data, replay, and rekey-as-data shapes.

## 6. In-chat commands (line REPL and TUI)

| Command | Behavior |
|---|---|
| `/quit` | Sends a Goodbye control frame, drains inbound ~2 s (so the peer's in-flight messages arrive and print), then 3-pass wipe + exit 0 |
| `/lock` | Locks the UI; PIN (`1234` demo) unlocks |
| `/unlock` | Unlocks; **duress PIN `0000` triggers the panic wipe** instead |
| `/copy` | Copies the last peer message; clipboard auto-clears after 5 s in a background thread (Wayland `wl-copy` zombies reaped) |
| Ctrl-C | Panic wipe + exit 0 |
| Esc (TUI) | Quit — restores terminal, sends goodbye + drains inbound ~2 s, then wipes |

Auto-lock: after `--auto-lock-secs` (default `1800` s) idle, the session
locks and demands the PIN. Dead-man: `--dead-man-secs` defaults to `0`
(disabled); the code's baseline constant is `1800`, but arming wipes +
exits — it is a deliberate operator choice.

## 7. Secure input

- `--secure-input` needs root + evdev; without root it warns and falls
  back to `/dev/tty`. Combining `--tui --secure-input` is a hard error:
  evdev grabbing feeds the line-mode reader only, and the TUI owns the
  keyboard — failing closed beats silently running unprotected.
- Input arrives over a channel fed by both stdin and the grabbed-keyboard
  reader; the evdev path retries on read errors.

## 8. HSM reporting

- `--hsm software` (default): Tier-1 RAM binding, prints its name and
  `isolates_keys=false`.
- `--hsm check`: additionally prints the hardware probe
  (`tpm2` / `yubikey-slot2-hmac` / `secure-enclave`, or "no hardware
  isolates found"-style output).
- Any other value prints a warning and falls back to software.

## 9. Exit codes

- Deliberate exits — `/quit`, Ctrl-C, peer goodbye/disconnect, dead-man,
  USBGuard, EOF, successful demo completion — are **`exit 0` after a
  3-pass wipe**.
- Error paths (`NullError`, `anyhow`) propagate a **nonzero** status before
  the wipe machinery runs. "Exited 0" is therefore meaningful: it means
  the wipe ran.

## 10. Known honest edge cases

- The TUI quit path (`Esc`) sends goodbye + drains inbound before wipe,
  matching the *live line-mode* quit path.
- `--control-port` provisioning failure prints an error but does not kill
  the session (you can still run over the pre-provisioned onion).
- The `listener` host and `NULL_DIRECT_ADDR` are test hooks; production
  discovery must use real `.onion` strings.