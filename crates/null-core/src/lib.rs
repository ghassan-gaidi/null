//! Null core types, constants, and errors (SUMMARY.md §3-§4, §13).
//!
//! Single source of truth for protocol versioning, frame geometry,
//! rekey policy, and connection-string parsing.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Protocol version. SUMMARY.md §6.1: 0x0002.
pub const PROTOCOL_VERSION: u16 = 0x0002;
/// Fixed network frame size — eliminates length-based traffic analysis.
pub const FRAME_SIZE: usize = 2048;
/// Frame header size (§6.1).
pub const FRAME_HEADER_SIZE: usize = 32;
/// Max encrypted payload bytes per frame: 2048 - 32 header - padding.
pub const MAX_PAYLOAD_SIZE: usize = 1984;
/// Poly1305 tag length.
pub const TAG_SIZE: usize = 16;
/// Kyber re-encapsulation interval: message count (§4.2).
pub const KYBER_REKEY_INTERVAL_MSGS: u64 = 50;
/// Kyber re-encapsulation interval: wall-clock bound (7 days).
pub const KYBER_REKEY_INTERVAL_SECS: u64 = 7 * 24 * 3600;
/// Token-bucket base rate: 1 frame / 2s (§6.2).
pub const SHAPER_BASE_INTERVAL_MS: u64 = 2000;
/// Token-bucket burst capacity.
pub const SHAPER_BURST: u32 = 5;
/// Clipboard auto-clear delay (5s, §8.2).
pub const CLIPBOARD_CLEAR_SECS: u64 = 5;
/// Dead man's switch default (30 min idle, §8.4).
pub const DEAD_MAN_SWITCH_SECS: u64 = 30 * 60;
/// Group size cap (MLS limit, §10).
pub const MAX_GROUP_MEMBERS: usize = 50_000;

#[derive(Debug, Error)]
pub enum NullError {
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("frame error: {0}")]
    Frame(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("memory error: {0}")]
    Memory(String),
    #[error("identity error: {0}")]
    Identity(String),
    #[error("group error: {0}")]
    Group(String),
    #[error("update error: {0}")]
    Update(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("invalid connection string: {0}")]
    ConnectionString(String),
    #[error("version downgrade: got {got}, expected >= {min}")]
    Downgrade { got: u64, min: u64 },
}

pub type Result<T> = std::result::Result<T, NullError>;

/// Frame types (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FrameType {
    Data = 0x01,
    Dummy = 0x02,
    Control = 0x03,
    KyberRekey = 0x04,
}

impl TryFrom<u8> for FrameType {
    type Error = NullError;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::Dummy),
            0x03 => Ok(Self::Control),
            0x04 => Ok(Self::KyberRekey),
            _ => Err(NullError::Frame(format!("unknown frame type {v:#x}"))),
        }
    }
}

/// Supported transports (§5.2), in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Tor,
    I2p,
    Nym,
    Snowflake,
    Webtunnel,
    Obfs4,
}

impl std::str::FromStr for TransportKind {
    type Err = NullError;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tor" => Ok(Self::Tor),
            "i2p" => Ok(Self::I2p),
            "nym" => Ok(Self::Nym),
            "snowflake" => Ok(Self::Snowflake),
            "webtunnel" => Ok(Self::Webtunnel),
            "obfs4" => Ok(Self::Obfs4),
            _ => Err(NullError::ConnectionString(format!(
                "unknown transport `{s}`"
            ))),
        }
    }
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Tor => "tor",
            Self::I2p => "i2p",
            Self::Nym => "nym",
            Self::Snowflake => "snowflake",
            Self::Webtunnel => "webtunnel",
            Self::Obfs4 => "obfs4",
        };
        write!(f, "{s}")
    }
}

/// Parsed `null://` connection string (§5.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionString {
    /// 56-char v3 onion host (without `.onion` suffix).
    /// The literal `listener` is accepted as a test hook for direct-TCP
    /// local handshakes (never valid on the real network).
    pub onion_host: String,
    /// Raw Kyber-1024 public key bytes (base64 in string form).
    pub kyber_pubkey_b64: String,
    /// Optional `ml-dsa:<hex>` identity fingerprint.
    pub identity_fingerprint: Option<String>,
    /// Transport priority list.
    pub transports: Vec<TransportKind>,
}

impl ConnectionString {
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix("null://")
            .ok_or_else(|| NullError::ConnectionString("missing null:// scheme".into()))?;
        let (host_part, query) = rest
            .split_once('?')
            .ok_or_else(|| NullError::ConnectionString("missing ?query".into()))?;
        let onion_host = host_part
            .strip_suffix(".onion")
            .ok_or_else(|| NullError::ConnectionString("missing .onion suffix".into()))?;
        if onion_host.len() != 56 && onion_host != "listener" {
            return Err(NullError::ConnectionString(format!(
                "onion host must be 56 chars, got {}",
                onion_host.len()
            )));
        }
        if !onion_host.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(NullError::ConnectionString(
                "onion host must be base32".into(),
            ));
        }
        let mut kyber_pubkey_b64 = None;
        let mut identity_fingerprint = None;
        let mut transports = vec![TransportKind::Tor, TransportKind::I2p, TransportKind::Nym];
        for part in query.split('&') {
            if let Some(k) = part.strip_prefix("k=") {
                if k.is_empty() {
                    return Err(NullError::ConnectionString("empty k=".into()));
                }
                kyber_pubkey_b64 = Some(k.to_string());
            } else if let Some(i) = part.strip_prefix("i=") {
                identity_fingerprint = Some(i.to_string());
            } else if let Some(t) = part.strip_prefix("t=") {
                transports = t
                    .split(',')
                    .map(|x| x.parse())
                    .collect::<Result<Vec<_>>>()?;
                if transports.is_empty() {
                    return Err(NullError::ConnectionString("empty t=".into()));
                }
            } else if part.is_empty() {
                continue;
            } else {
                // Unknown query keys are ignored for forward compatibility,
                // except a bare base64 blob is treated as the kyber key
                // (matches SUMMARY.md example `?...?[kyber]&...` shorthand).
                if kyber_pubkey_b64.is_none() && !part.contains('=') {
                    kyber_pubkey_b64 = Some(part.to_string());
                }
            }
        }
        let kyber_pubkey_b64 = kyber_pubkey_b64
            .ok_or_else(|| NullError::ConnectionString("missing kyber pubkey (k=)".into()))?;
        Ok(Self {
            onion_host: onion_host.to_string(),
            kyber_pubkey_b64,
            identity_fingerprint,
            transports,
        })
    }

    pub fn to_uri(&self) -> String {
        let mut s = format!(
            "null://{}.onion?k={}",
            self.onion_host, self.kyber_pubkey_b64
        );
        if let Some(i) = &self.identity_fingerprint {
            s.push_str(&format!("&i={i}"));
        }
        let t = self
            .transports
            .iter()
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
            .join(",");
        s.push_str(&format!("&t={t}"));
        s
    }
}

impl std::fmt::Display for ConnectionString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_uri())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_connection_string() {
        let onion = "zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad";
        let s = format!("null://{onion}.onion?k=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA&i=ml-dsa:ABCD&t=tor,i2p,nym");
        let cs = ConnectionString::parse(&s).unwrap();
        assert_eq!(cs.onion_host, onion);
        assert_eq!(
            cs.transports,
            vec![TransportKind::Tor, TransportKind::I2p, TransportKind::Nym]
        );
        assert_eq!(cs.identity_fingerprint.as_deref(), Some("ml-dsa:ABCD"));
    }

    #[test]
    fn reject_bad_onion_len() {
        assert!(ConnectionString::parse("null://short.onion?k=abc").is_err());
    }

    #[test]
    fn roundtrip() {
        let cs = ConnectionString {
            onion_host: "a".repeat(56),
            kyber_pubkey_b64: "S0VZ".into(),
            identity_fingerprint: None,
            transports: vec![TransportKind::Tor],
        };
        let s = cs.to_uri();
        assert_eq!(ConnectionString::parse(&s).unwrap(), cs);
    }
}
