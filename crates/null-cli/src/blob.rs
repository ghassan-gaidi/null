//! Shared stdio-blob conventions for pipe-oriented subcommands:
//! base64 blobs via explicit arg or stdin, `LABEL:base64` lines on stdout,
//! human chatter on stderr. State lives in pipes/shell vars — RAM only.

use anyhow::Result;

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| anyhow::anyhow!("bad base64: {e}"))
}

pub fn b64_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

pub fn hex_encode(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push(H[(byte >> 4) as usize] as char);
        s.push(H[(byte & 15) as usize] as char);
    }
    s
}

/// Blob input: explicit arg, else stdin (so `... | null <verb>` works).
pub fn read_blob(arg: &Option<String>) -> Result<Vec<u8>> {
    let s = match arg {
        Some(v) => v.clone(),
        None => {
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
            buf
        }
    };
    b64_decode(&s)
}

/// Null-error to anyhow with a verb tag (the codebase maps instead of
/// `From`, so every fallible call sites this helper).
pub fn grp<T>(r: null_core::Result<T>, what: &str) -> Result<T> {
    r.map_err(|e| anyhow::anyhow!("{what}: {e}"))
}
