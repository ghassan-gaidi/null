# Transports & traffic analysis

How Null moves bytes without leaking where they came from. Two layers,
cleanly separated: **null-transport** (dialing, multiplexer, blob pipes)
and **null-frame** (fixed-size frames, token bucket, dummies).

## 1. The daemon/sidecar model

Null never embeds Tor or another anon daemon. Each transport dials a
**local daemon**, and `null-transport` is agnostic to which daemon answers:

| Transport kind | Local daemon protocol | Default endpoint |
|---|---|---|
| `tor` | SOCKS5 (RFC 1928) + Tor control for onion provisioning | socks `127.0.0.1:9050`, control `9051` |
| `i2p` | SAMv3 (`HELLO`/`SESSION CREATE`/`STREAM CONNECT`) | control `127.0.0.1:7656`, socks `4447` |
| `nym` | SOCKS5 through the local nym-client gateway | socks `127.0.0.1:1080`, control `1977` |
| `snowflake` | Pluggable-transport sidecar (WebRTC bridges) | requires managed PT binary |
| `webtunnel` | Pluggable-transport sidecar (HTTPS cover) | requires managed PT binary |
| `obfs4` | Pluggable-transport sidecar | requires managed PT binary |

- **SOCKS5** (`null-transport/live.rs`): no-auth greeting `[0x05,0x01,0x00]`,
  CONNECT with ATYP `0x03` (domain) so `.onion` names are resolved by the
  proxy — **no local DNS leak** — and response parsing covers ATYP 1/3/4.
  All I/O under a 10-second timeout.
- **SAMv3** (`live.rs`): `HELLO VERSION MIN=3.0 MAX=3.1`, `SESSION CREATE
  STYLE=STREAM ID=<nickname> DESTINATION=TRANSIENT`, then
  `STREAM CONNECT … DESTINATION=…`.
- **Tor control** (`live.rs`): minimal `AUTHENTICATE` (cookie or password)
  + `ADD_ONION NEW:BEST Port=<virtport>,127.0.0.1:auto`, parses
  `250-ServiceID=<id>`, returns `<id>.onion`; 5xx responses are errors.

## 2. Stub vs live

`define_transport!`'s `dial_ep` probes the daemon's SOCKS port with a
150 ms TCP connect first:

- Daemon present → real circuit.
- Daemon absent + `NULL_LIVE_TRANSPORT=1` → **hard error** with
  remediation text (never fake connectivity).
- Daemon absent + flag unset → a **virtual stub circuit** for tests and
  demos (no bytes leave the process).

`dial_live_ep` never stubs. Producing real bytes always requires
`NULL_LIVE_TRANSPORT=1` on the dialing side; a principal test hook,
`NULL_DIRECT_ADDR`, dials a raw loopback TCP address for a `null://`
string whose host is the literal `listener` (never valid on the real
network).

The failover entry point is named what it is: `Multiplexer::dial_stub`.
Loopback and tests call it openly; the CLI refuses to hand a stub to a
real `.onion` peer — without `NULL_LIVE_TRANSPORT=1` it errors before
any handshake (`transport_cli.rs` pins this), so a stub can never be
mistaken for live failover.

## 3. Multiplexer: election and failover

`Multiplexer::new(priority)` builds all six backends with per-transport
stats and elects by modeled latency plus jitter:

| Transport | Modeled base latency | Uniform jitter |
|---|---|---|
| tor | 350 ms | 0–199 ms |
| obfs4 | 380 ms | 0–199 ms |
| webtunnel | 420 ms | 0–199 ms |
| snowflake | 700 ms | 0–199 ms |
| i2p | 900 ms | 0–199 ms |
| nym | 1400 ms | 0–199 ms |

Election adds a **50 ms/rank priority tie-break**; the fallback transport
is always `tor`. `dial`/`dial_live` iterate the priority list, first
success wins, failures are counted (`TransportStats`), and a failed path is
bypassed on the next dial — transparent failover with zero user action.

## 4. Fixed-size frames and the token bucket (`null-frame`)

Every frame is exactly **2048 bytes** regardless of content
(`docs/wire-protocol.md` §3). This is the anti-traffic-analysis layer:

- **Shaper**: token bucket with capacity `5` (`SHAPER_BURST`), refill
  0.5 tokens/s — i.e. 1 frame per `2000` ms (`SHAPER_BASE_INTERVAL_MS`).
  A full burst is available at session start, so the first messages are
  not delayed.
- **Jitter**: `next_delay()` samples a **single uniform u64** and maps it
  to 1.0–3.0 s (mean 2 s), clamped 0.5–4.0 s. The distribution is uniform,
  not a normal — deliberately: a uniform sample cannot fingerprint the RNG
  or a clock-skew distribution.
- **Dummies**: when idle, line and TUI chat loops emit
  `Frame::dummy(counter)` (64 random payload bytes, otherwise identical to
  data frames) at the shaped rate. A Dummy frame decrypts to garbage and
  is dropped silently — but it is indistinguishable in size, timing, and
  format from real traffic.
- Frame types: `Data(0x01)`, `Dummy(0x02)`, `Control(0x03)`,
  `KyberRekey(0x04)`; version must be `0x0002`.

Padded, shaped, cover-traffic framing is enforced by the chat loops in
`null-cli` (line and TUI) whenever a transport is involved — loopback demo
included.

## 5. Connection lifecycle

- **Blob framing**: `u32 BE length ‖ bytes`, ≤ 16 MiB, 120 s receive
  timeout (`docs/wire-protocol.md` §2). This gives peers whole-frame
  boundaries without byte-stuffing.
- **Orderly quit**: a `Goodbye` control frame is sent *first*, then the
  peer's inbound is drained ~2 s. Draining the receive buffer after
  sending goodbye is what prevents the local close from RST-discarding the
  peer's queued bytes.
- **Peer disappearance**: FIN/RST → drain what arrived, then panic-wipe
  and exit 0.

## 6. Bridge transports (Snowflake / WebTunnel / obfs4)

These need operator-installed **pluggable-transport client binaries**. The
live path validates the binary via `ensure_pt` (runs `<binary> -h`) and
emits ready-to-use torrc lines:

```
UseBridges 1
ClientTransportPlugin <kind> exec /usr/bin/<kind>
Bridge <bridge_line>
```

Without a sidecar the dial fails closed with exactly this remediation
text. Note that the PT *name* and the shipped *binary* differ
(`obfs4` → `obfs4proxy`, `snowflake` → `snowflake-client`,
`webtunnel` → `webtunnel-client`), which the emitted lines get right —
Tor's plugin name is `obfs4`, not `obfs4proxy`. Rendezvous/front-domain
default to placeholders (`snowflake-null-rendezvous`, `cdn.null.invalid`)
until the operator configures real values: `--snowflake-rendezvous` /
`--webtunnel-front` flags, else `$NULL_SNOWFLAKE_RENDEZVOUS` /
`$NULL_WEBTUNNEL_FRONT` env, applied identically at both chat entry
points — see `docs/operations.md` and `contrib/` for the deployment
runbook.

obfs4 also ships a scrambling layer for the stub path: a uniform-DH-style
keystream `SHA256(secret ‖ counter)` XOR applied in 32-byte blocks,
reversible (roundtrip-tested).

## 7. Operational checklist

- Install and configure your anon daemons **before** trusting Null for
  metadata resistance: `tor` (SOCKS 9050), `i2pd`/`java` I2P (SAM 7656),
  `nymph` (SOCKS 1080).
- For bridges: install `obfs4proxy`, `snowflake-client`, or the WebTunnel
  client and pass bridge lines per the torrc templates above.
- Terminals without daemons are fine for the loopback demo (`--peer
  loopback`) — nothing leaves the machine.
- Real bytes require `NULL_LIVE_TRANSPORT=1` on the initiator and an onion
  service in front of the listener (`--listen` + `--control-port 9051`).
- Understand that transports provide **metadata minimization, not
  signature**: E2E security holds even over a hostile channel (proven in
  the Tamarin handshake model, which assumes a Dolev-Yao network); what a
  bad bridge can do is observe *timing and volume* — which the fixed
  frames, shaper, and dummies are designed to flatten.