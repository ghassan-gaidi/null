# Operations runbook

What an operator actually does to run Null safely in production: daemon
setup, bridge provisioning, key lifecycle, multi-device management, and
incident response.

## 1. Baseline: the daemons

Null dials local daemons; metadata resistance is only as good as the
daemons you run. Minimum layout for real use:

| Transport | Daemon | Config you must provide |
|---|---|---|
| Tor | `tor` | `SocksPort 9050`, `ControlPort 9051` (for onion provisioning), `CookieAuthentication 1` |
| I2P | `i2pd` or Java I2P | SAM enabled on `127.0.0.1:7656` |
| Nym | `nymph` client | SOCKS gateway on `127.0.0.1:1080` |
| Snowflake/WebTunnel/obfs4 | PT client binaries | see §3 |

Health-check the same way the code does before trusting a circuit: a
150 ms TCP probe to the SOCKS/control port. `NULL_LIVE_TRANSPORT=1` makes
a missing daemon a hard error instead of a silent stub — **always run with
it set in production**.

## 2. Listening + discovery

```
# Responder: bind loopback, optionally provision an ephemeral onion
null --listen 18080 --control-port 9051 --transports tor   # prints null:// string

# Initiator: dial over real Tor
NULL_LIVE_TRANSPORT=1 null --peer 'null://<onion-host>.onion?k=<b64>&i=<ml-dsa:fp>'
```

- The `--listen` string's `k=` is the listener's long-term ML-KEM-1024 ek;
  share it out-of-band **together with** the `i=` fingerprint in verified
  mode. Sharing `k=` without `i=` establishes encryption but **not
  authentication** (TOFU).
- Front `--listen` with your own onion service if you disable
  `--control-port`; the port binds `127.0.0.1` only.
- The literal host `listener` + `NULL_DIRECT_ADDR` are for tests; never
  use them for real peers.

## 3. Bridge provisioning (Snowflake / WebTunnel / obfs4)

1. Install the client binary (`obfs4proxy` / `snowflake-client` / your
   WebTunnel client) system-wide.
2. Obtain a bridge line from your bridge operator:
   `Bridge obfs4 <ip>:<port> <fingerprint> …`.
3. Make sure the transport can start: `null`'s live path runs
   `ensure_pt(<binary>)` (a `-h` probe), then you can feed torrc lines it
   emits (`UseBridges 1` / `ClientTransportPlugin <kind> exec …` /
   `Bridge …`) into your Tor config.
4. Verify with `NULL_LIVE_TRANSPORT=1` that a circuit actually
   establishes; a bridge that fails closed with remediation text is the
   designed behavior, not a bug.
5. For your **own** bridge server: run the PT server side (obfs4 bridge,
   snowflake broker, WebTunnel server) on a host that can survive DPI;
   distribute bridge lines out-of-band to clients. The client-side config
   here is just the dialing half.

### Copy-pasteable configs

`contrib/` holds the shapes we test against, so deployment is
copy-edit-run rather than improvisation: `contrib/tor/null-responder.torrc`
(persistent v3 onion service), `contrib/tor/bridge-client.torrc` (PT
dialing), `contrib/tor/bridge-server-obfs4.torrc` (bridge relay side),
`contrib/systemd/null-responder.service` (supervised responder), and
`contrib/systemd/obfs4proxy-server.service`. Start with
`contrib/README.md`.

Two operational facts the templates encode, because getting them wrong
looks like "Null is broken":

- **The responder serves one session per process.** It binds
  `127.0.0.1:<port>`, serves exactly one inbound handshake, then wipes and
  exits when that peer leaves. Supervise it; do not expect a resident
  daemon.
- **The responder needs a TTY.** Both chat modes read stdin, and EOF there
  means "send goodbye and exit", so a unit with `StandardInput=null`
  exits immediately. The shipped unit runs it under `tmux` for a real pty.
  Null has no headless receive-only mode.

A bridge changes *who can reach* your onion service; it is not an
authentication factor. Peer identity is the safety number's job (§4).

## 4. Verified deployments (authentication)

- Every participant's `null://` string must carry `i=<ml-dsa:fingerprint>`
  and the fingerprint must be checked **out-of-band at least once**
  (voice call, QR scan at a meetup, published on the org's key page with
  a separate channel verifying that page).
- After first verification, keep the transparency checkpoint
  (`null-kt-v1:<contact>:…`) — a changed key for the contact fails closed
  ("possible MITM") by design.
- Never mix modes for the same contact: deniable ↔ verified transcripts
  are different security claims (`docs/deniability.md`).

## 5. Key lifecycle

| Key | Lifecycle |
|---|---|
| Session ephemerals (X25519, Kyber) | Fresh per session/message; wiped on exit; nothing to rotate |
| Listener long-term Kyber ek (`k=`) | Regenerated every `--listen` run; share fresh strings out-of-band. A leaked ek means a *harvested* identity for MITM until next run — but zero past-ciphertext risk because *all* key material is ephemeral + RAM-only |
| ML-DSA identity (`IdentityKey`) | Derived from a 32-byte seed, held in RAM only; prints as `i=` fingerprint. No disk persistence — a fresh run reprovisions identities |
| Device ids | `SHA3-256(seed ‖ "Null-v2.0-device:" ‖ slot)` — stable per (identity, slot), no disk |
| Release keys | Offline, split, HSM-adjacent; ceremony in `docs/release.md` |

Because everything is RAM-only and regenerated per run, "rotation" is
simply "re-share a fresh string." The cost: identities do not survive a
reboot — a deliberate trade for zero on-disk residue.

## 6. Multi-device operations

- One identity, N devices: each device derives its device id from its own
  seed; group membership uses `device_member_id` =
  `SHA3-256("Null-v2.0-device-member:" ‖ fp ‖ device_id)`.
- `DeviceSet` tracks `(kyber_ek, revoked, added_epoch)` per device; a
  revoked (or unknown) device id counts as revoked — fail closed
  (`docs/multidevice.md`, `docs/memory-hardening.md`).
- Revocation is a *manual coordination event* between devices (no central
  server): perform it on a trusted device and propagate the updated set
  through the same out-of-band channel you use for strings.

## 7. Incident response

| Incident | Runbook |
|---|---|
| Suspected endpoint compromise | Kill `null` (`Ctrl-C` triggers wipe); reboot; re-share fresh `null://` strings out-of-band; re-verify fingerprints; rotate group devices (remove + re-add each) |
| Suspicious key change on a contact | Transparency log fails closed ("possible MITM"): stop, verify the new fingerprint out-of-band before continuing; treat the old session as compromised |
| Rekey request loop / "PQ resync impossible" | Session refuses to continue silently (by design): re-handshake with a fresh string |
| Suspected release-key compromise | Treat as catastrophic (`docs/updates.md`); publish a new manifest with rotated keys at a higher version immediately; notify security contacts per `SECURITY.md` |
| Dead-man/duress wipe fired | Assume anything in RAM is gone (that's the point); wipe disk forensically only if disks ever touched this machine; re-establish all sessions fresh |
| Sidecar/daemon compromise | Traffic remains E2E-encrypted; the exposure is metadata (timing/volume flattened by shaping) — stop the daemon, replace the binary, verify checksums |
| Upstream dependency CVE | `cargo audit` gates; pin + bump in `Cargo.lock`, re-run all gates, ship a new signed manifest (downgrade floor protects clients until they get it) |
| Bad update installed | The downgrade floor forbids re-applying older manifests — rollback is manual: keep a backup of the working binary before `apply` (`cp null null.prev`), restore by copying back. Never bypass verification to "go back faster" |

## 8. Logging & monitoring posture

- Null writes **nothing to disk** — no logs to leak, but also no
  forensics of your own. For audits, wrap the invocation:
  `ts`/`script` to a RAM-backed tmpfs if you must record a session trace.
- Don't run `null` under strace/gdb without accepting the ptrace exposure;
  `PR_SET_DUMPABLE=0` will refuse dumps.
- On multi-user systems, run under a dedicated unprivileged user; root is
  only required for `--secure-input`.

## 9. Prerelease checklist

- `cargo run -p xtask -- repro` (bit-identical build).
- `cargo run -p xtask -- kat --check` and `doccheck` green locally.
- Signed manifest produced with the offline ceremony (`docs/release.md`).
- New `null://` strings shared out-of-band for every identity/pair you
  deploy.