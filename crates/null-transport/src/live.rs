//! Live network paths (§5): SOCKS5 dialing, Tor control-port onion
//! provisioning, I2P SAM sessions, and pluggable-transport supervision.
//!
//! All live paths degrade to descriptive errors when daemons are absent;
//! nothing here fabricates connectivity. Unit tests run against local stub
//! servers, never the public network.

use null_core::{NullError, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const IO_TIMEOUT: Duration = Duration::from_secs(10);

async fn read_exact_n(stream: &mut tokio::net::TcpStream, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut buf))
        .await
        .map_err(|_| NullError::Transport("read timeout".into()))?
        .map_err(|e| NullError::Transport(format!("read: {e}")))?;
    Ok(buf)
}

async fn read_line_capped(stream: &mut tokio::net::TcpStream) -> Result<String> {
    let mut out = Vec::new();
    loop {
        let b = read_exact_n(stream, 1).await?;
        out.push(b[0]);
        if b[0] == b'\n' || out.len() > 8192 {
            break;
        }
    }
    String::from_utf8(out).map_err(|_| NullError::Transport("non-utf8 reply".into()))
}

// ---------------------------------------------------------------------------
// SOCKS5 CONNECT (RFC 1928), no-auth. Domain names (incl. .onion) are sent
// as ATYP 0x03 so the proxy resolves them — never leak DNS locally.
// ---------------------------------------------------------------------------

/// Open `target` through the SOCKS5 proxy at `proxy_addr`
/// (e.g. `127.0.0.1:9050`). Returns the connected stream on success.
pub async fn socks5_connect(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<tokio::net::TcpStream> {
    let mut s = tokio::time::timeout(IO_TIMEOUT, tokio::net::TcpStream::connect(proxy_addr))
        .await
        .map_err(|_| NullError::Transport(format!("socks proxy unreachable at {proxy_addr}")))?
        .map_err(|e| NullError::Transport(format!("socks connect: {e}")))?;
    // Greeting: version 5, 1 method, no-auth.
    s.write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| NullError::Transport(format!("socks greeting: {e}")))?;
    let resp = read_exact_n(&mut s, 2).await?;
    if resp != [0x05, 0x00] {
        return Err(NullError::Transport(format!(
            "socks proxy rejected no-auth ({resp:?})"
        )));
    }
    // Request: CONNECT + domain.
    if target_host.len() > 255 {
        return Err(NullError::Transport("target hostname too long".into()));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, target_host.len() as u8];
    req.extend_from_slice(target_host.as_bytes());
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req)
        .await
        .map_err(|e| NullError::Transport(format!("socks request: {e}")))?;
    let hdr = read_exact_n(&mut s, 4).await?;
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        return Err(NullError::Transport(format!(
            "socks connect failed (rep={:#04x})",
            hdr[1]
        )));
    }
    // Consume BND.ADDR + BND.PORT per ATYP.
    match hdr[3] {
        0x01 => {
            read_exact_n(&mut s, 6).await?;
        }
        0x03 => {
            let n = read_exact_n(&mut s, 1).await?[0] as usize;
            read_exact_n(&mut s, n + 2).await?;
        }
        0x04 => {
            read_exact_n(&mut s, 18).await?;
        }
        _ => return Err(NullError::Transport("bad socks atyp".into())),
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// Tor control protocol: ephemeral onion service provisioning.
// ---------------------------------------------------------------------------

/// Minimal Tor control-port client (cookie/none auth).
pub struct TorController {
    stream: tokio::net::TcpStream,
}

impl TorController {
    pub async fn connect(control_addr: &str, password: Option<&str>) -> Result<Self> {
        let mut stream =
            tokio::time::timeout(IO_TIMEOUT, tokio::net::TcpStream::connect(control_addr))
                .await
                .map_err(|_| {
                    NullError::Transport(format!("tor control unreachable at {control_addr}"))
                })?
                .map_err(|e| NullError::Transport(format!("tor control: {e}")))?;
        let auth = match password {
            Some(p) => format!("AUTHENTICATE \"{p}\"\r\n"),
            None => "AUTHENTICATE\r\n".to_string(),
        };
        stream
            .write_all(auth.as_bytes())
            .await
            .map_err(|e| NullError::Transport(format!("tor auth write: {e}")))?;
        let line = read_line_capped(&mut stream).await?;
        if !line.starts_with("250") {
            return Err(NullError::Transport(format!("tor auth rejected: {line}")));
        }
        Ok(Self { stream })
    }

    /// Create an ephemeral v3 onion service forwarding `virtport` to
    /// `target` (e.g. `127.0.0.1:auto`). Returns the full `.onion` hostname.
    pub async fn add_onion(&mut self, virtport: u16, target: &str) -> Result<String> {
        let cmd = format!("ADD_ONION NEW:BEST Port={virtport},{target}\r\n");
        self.stream
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| NullError::Transport(format!("add_onion write: {e}")))?;
        // Multiline 250-... ending in `250 OK` (or `250 ServiceID=...`).
        loop {
            let line = self.read_line().await?;
            if let Some(id) = line.strip_prefix("250-ServiceID=") {
                let host = format!("{}.onion", id.trim());
                // Drain to final OK.
                loop {
                    let l = self.read_line().await?;
                    if l.starts_with("250 ") || l.starts_with("250\r") {
                        break;
                    }
                }
                return Ok(host);
            }
            if line.starts_with("250 ") {
                if line.contains("ServiceID=") {
                    let id = line
                        .split("ServiceID=")
                        .nth(1)
                        .and_then(|s| s.split_whitespace().next())
                        .ok_or_else(|| NullError::Transport("malformed ServiceID reply".into()))?;
                    return Ok(format!("{id}.onion"));
                }
                return Err(NullError::Transport(
                    "ADD_ONION ok without ServiceID".into(),
                ));
            }
            if line.starts_with('5') {
                return Err(NullError::Transport(format!("ADD_ONION failed: {line}")));
            }
        }
    }

    async fn read_line(&mut self) -> Result<String> {
        read_line_capped(&mut self.stream).await
    }
}

// ---------------------------------------------------------------------------
// I2P SAMv3 session + STREAM CONNECT.
// ---------------------------------------------------------------------------

/// Minimal SAMv3 client (stream style) against e.g. `127.0.0.1:7656`.
pub struct SamSession {
    stream: tokio::net::TcpStream,
    id: String,
}

impl SamSession {
    pub async fn create(sam_addr: &str, nickname: &str) -> Result<Self> {
        let mut stream = tokio::time::timeout(IO_TIMEOUT, tokio::net::TcpStream::connect(sam_addr))
            .await
            .map_err(|_| NullError::Transport(format!("SAM unreachable at {sam_addr}")))?
            .map_err(|e| NullError::Transport(format!("SAM connect: {e}")))?;
        stream
            .write_all(b"HELLO VERSION MIN=3.0 MAX=3.1\n")
            .await
            .map_err(|e| NullError::Transport(format!("SAM hello: {e}")))?;
        let line = read_line_capped(&mut stream).await?;
        if !line.contains("RESULT=OK") {
            return Err(NullError::Transport(format!("SAM hello rejected: {line}")));
        }
        let cmd = format!("SESSION CREATE STYLE=STREAM ID={nickname} DESTINATION=TRANSIENT\n");
        stream
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| NullError::Transport(format!("SAM session: {e}")))?;
        let line = read_line_capped(&mut stream).await?;
        if !line.contains("RESULT=OK") {
            return Err(NullError::Transport(format!(
                "SAM session rejected: {line}"
            )));
        }
        Ok(Self {
            stream,
            id: nickname.to_string(),
        })
    }

    /// Connect a stream to `destination_b32` (.b32.i2p name or full dest).
    pub async fn stream_connect(mut self, destination_b32: &str) -> Result<tokio::net::TcpStream> {
        let cmd = format!(
            "STREAM CONNECT ID={} DESTINATION={} SILENT=false\n",
            self.id, destination_b32
        );
        self.stream
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| NullError::Transport(format!("SAM connect write: {e}")))?;
        let line = read_line_capped(&mut self.stream).await?;
        if !line.contains("RESULT=OK") {
            return Err(NullError::Transport(format!("SAM stream rejected: {line}")));
        }
        Ok(self.stream)
    }
}

// ---------------------------------------------------------------------------
// Pluggable transports: supervised sidecar binaries.
// ---------------------------------------------------------------------------

/// Check that a pluggable-transport client binary exists and runs.
/// Returns its first version line, or a remediation error.
pub fn ensure_pt(binary: &str) -> Result<String> {
    let out = std::process::Command::new(binary)
        .arg("-h")
        .output()
        .map_err(|_| {
            NullError::Transport(format!(
                "`{binary}` not installed — try your distro's `obfs4proxy`/`snowflake` package"
            ))
        })?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(text.lines().next().unwrap_or("").to_string())
}

/// Recommended `torrc` client lines for a bridge transport.
pub fn torrc_bridge_lines(kind: &str, bridge_line: &str) -> String {
    format!(
        "UseBridges 1\nClientTransportPlugin {kind} exec /usr/bin/{kind}\nBridge {bridge_line}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn stub_server(script: Vec<StubStep>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            for step in script {
                match step {
                    StubStep::ExpectBytes(n) => {
                        let mut b = vec![0u8; n];
                        s.read_exact(&mut b).await.unwrap();
                    }
                    StubStep::ExpectLinePrefix(p) => {
                        let mut line = vec![];
                        loop {
                            let mut b = [0u8; 1];
                            s.read_exact(&mut b).await.unwrap();
                            line.push(b[0]);
                            if b[0] == b'\n' {
                                break;
                            }
                        }
                        let text = String::from_utf8(line).unwrap();
                        assert!(text.starts_with(&p), "expected prefix {p:?}, got {text:?}");
                    }
                    StubStep::Send(b) => {
                        s.write_all(&b).await.unwrap();
                    }
                }
            }
        });
        addr
    }

    enum StubStep {
        ExpectBytes(usize),
        ExpectLinePrefix(String),
        Send(Vec<u8>),
    }

    #[tokio::test]
    async fn socks5_connect_ok() {
        let addr = stub_server(vec![
            StubStep::ExpectBytes(3),
            StubStep::Send(vec![0x05, 0x00]),
            StubStep::ExpectBytes(4 + 1 + 22 + 2), // CONNECT zqkt... (22-char test host)
            StubStep::Send(vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
        ])
        .await;
        let host = "a".repeat(22);
        let _s = socks5_connect(&addr, &host, 80).await.unwrap();
    }

    #[tokio::test]
    async fn socks5_rejects_bad_method() {
        let addr = stub_server(vec![
            StubStep::ExpectBytes(3),
            StubStep::Send(vec![0x05, 0xFF]),
        ])
        .await;
        assert!(socks5_connect(&addr, "example.onion", 80).await.is_err());
    }

    #[tokio::test]
    async fn tor_add_onion_parses_service_id() {
        let service = "zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad";
        let addr = stub_server(vec![
            StubStep::ExpectLinePrefix("AUTHENTICATE".into()),
            StubStep::Send(b"250 OK\r\n".to_vec()),
            StubStep::ExpectLinePrefix("ADD_ONION".into()),
            StubStep::Send(format!("250-ServiceID={service}\r\n250 OK\r\n").into_bytes()),
        ])
        .await;
        let mut ctl = TorController::connect(&addr, None).await.unwrap();
        let host = ctl.add_onion(80, "127.0.0.1:auto").await.unwrap();
        assert_eq!(host, format!("{service}.onion"));
    }

    #[tokio::test]
    async fn sam_stream_connect_ok() {
        let addr = stub_server(vec![
            StubStep::ExpectLinePrefix("HELLO VERSION".into()),
            StubStep::Send(b"HELLO REPLY RESULT=OK VERSION=3.1\n".to_vec()),
            StubStep::ExpectLinePrefix("SESSION CREATE".into()),
            StubStep::Send(b"SESSION STATUS RESULT=OK\n".to_vec()),
            StubStep::ExpectLinePrefix("STREAM CONNECT".into()),
            StubStep::Send(b"STREAM STATUS RESULT=OK\n".to_vec()),
        ])
        .await;
        let sess = SamSession::create(&addr, "nulltest").await.unwrap();
        let _s = sess.stream_connect("peer.b32.i2p").await.unwrap();
    }

    #[test]
    fn torrc_lines_shape() {
        let s = torrc_bridge_lines("obfs4", "obfs4 1.2.3.4:443 CERT=abc");
        assert!(s.contains("UseBridges 1"));
        assert!(s.contains("Bridge obfs4"));
    }

    #[tokio::test]
    async fn blob_roundtrip_over_tcp() {
        use crate::{Endpoint, TransportConn, TransportKind};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = TransportConn::new_live(
                TransportKind::Tor,
                Endpoint {
                    onion_host: "x".into(),
                    port: 80,
                },
                stream,
            );
            let got = conn.recv_blob().await.unwrap();
            assert_eq!(got, b"hello-blob");
            conn.send_blob(b"ack-blob").await.unwrap();
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = TransportConn::new_live(
            TransportKind::Tor,
            Endpoint {
                onion_host: "x".into(),
                port: 80,
            },
            stream,
        );
        conn.send_blob(b"hello-blob").await.unwrap();
        let ack = conn.recv_blob().await.unwrap();
        assert_eq!(ack, b"ack-blob");
        server.await.unwrap();
    }
}
