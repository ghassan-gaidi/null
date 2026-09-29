# Operator runbook: onion + bridge deployment

Everything in this directory is **operator-run scaffolding**. Null ships no
daemon that fronts your anonymity network for you: the Tor (or I2P / Nym)
daemon, the onion service, and any pluggable-transport binary are all
yours to install, patch, and audit. This directory gives you the exact
config shapes we test against, so deployment is copy-edit-run rather than
improvisation.

| File | Role |
|---|---|
| `tor/null-responder.torrc` | Persistent v3 onion service fronting a local `null --listen` port |
| `tor/bridge-client.torrc` | Client-side bridge dialing (`UseBridges` + PT plugin) |
| `tor/bridge-server-obfs4.torrc` | Operator-run obfs4 **bridge** (the server half) |
| `systemd/null-responder.service` | Responder under a pty (tmux), restarted per session |
| `systemd/obfs4proxy-server.service` | obfs4 bridge sidecar |

Long-form narrative lives in `docs/operations.md`; this file is the
copy-pasteable part.

## 0. Two facts that shape every deployment here

1. **The responder is one session per process.** `null --listen` binds
   `127.0.0.1:<port>`, serves exactly one inbound handshake, and wipes and
   exits when that peer leaves. Supervise it (see the systemd unit) rather
   than expecting a daemon that stays up.
2. **The responder needs a TTY.** Both chat modes (line and `--tui`) read
   keystrokes; when stdin hits EOF the process sends a goodbye frame and
   exits. `StandardInput=null` therefore *kills the responder immediately*.
   The unit below runs it under `tmux` so it gets a real pty. If you do
   not want `tmux`, any pty supervisor works; Null has no headless
   receive-only mode, and pretending otherwise is how you end up with a
   service that quietly never answers.

## 1. Responder (you are being contacted)

```bash
# 1. Tor with our onion config (drops a hostname in the service dir).
sudo install -d -m 0700 -o debian-tor -g debian-tor /etc/tor
sudo install -m 0644 -o root -g root contrib/tor/null-responder.torrc /etc/tor/null-responder.torrc
sudo systemctl reload tor      # or: tor --verify-config && systemctl restart tor
cat /var/lib/tor/null-responder/hostname   # <- this is your contact address

# 2. Responder (pty + supervision).
sudo install -m 0644 contrib/systemd/null-responder.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now null-responder

# 3. Read the null:// string the responder prints (once per process start).
sudo journalctl -u null-responder -n 40 --no-pager
```

Share the printed `null://` string **out of band**. In verified mode it
carries `i=<ml-dsa fingerprint>`; the fingerprint must be confirmed in
person (or over a channel you already trust) — a fingerprint exchanged
over the same session you are trying to authenticate proves nothing.

## 2. Initiator (you are contacting someone)

```bash
# Your Tor daemon must be able to reach .onion (SOCKS 9050 by default).
NULL_LIVE_TRANSPORT=1 null --peer 'null://<56-char-onion>:…' --verified
```

`NULL_LIVE_TRANSPORT=1` is the deliberate opt-in: without it the CLI runs
the stub transport so demos and tests never touch the network. If you see
"stub — set NULL_LIVE_TRANSPORT=1", no bytes moved.

## 3. Bridge deployment (censored networks)

Null does not implement a censorship-resistant transport itself; it uses
Tor's pluggable transports. The remediation lines the CLI prints
(`torrc_bridge_lines`) are the shape below, with the shipped binary name
(`obfs4proxy`, not `obfs4`):

```
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
Bridge obfs4 <ip>:<port> <fingerprint> cert=<base64> iat-mode=0
```

- **Client side:** install the PT binary (`obfs4proxy` on Debian/Ubuntu),
  append `contrib/tor/bridge-client.torrc` to your torrc, and get the
  bridge line from your bridge operator. Then dial the responder's onion as
  usual — the onion address does not change, only the path to it.
- **Server side (your own bridge):** `contrib/tor/bridge-server-obfs4.torrc`
  plus `systemd/obfs4proxy-server.service`. Run it on a host that survives
  DPI, keep it updated, and distribute bridge lines out of band.

**Do not treat a bridge as an authentication factor.** A bridge changes
who can reach your onion service; it says nothing about whether the peer
on the other end is who they claim to be. That is the safety number's job
(`docs/operations.md` §4).

## 4. Verify the deployment

```bash
# Onion service reachable and the responder waiting:
sudo ss -ltnp | grep 8077                     # local listener bound
sudo journalctl -u null-responder -f          # expect the null:// banner
# Tor circuit established (from the initiator host):
journalctl -u tor -f | grep -i 'circuit.*built\|Bootstrapped 100'
# End-to-end: a real session, then a clean goodbye + wipe.
```

A silent responder is almost always one of: stdin at EOF (fact 2 above),
the listener never started (`systemctl status`), Tor not bootstrapped, or
a bridge line the PT binary refuses. All four fail closed with a message
rather than degrading into an unauthenticated session — that is the
intended behavior, so read the log rather than routing around it.
