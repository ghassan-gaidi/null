//! Transport realism through the `null` binary: operator PT overrides
//! are accepted, and real `.onion` peers without live transport fail
//! loudly instead of parking on a stub circuit.

use std::process::{Command, Stdio};

fn bin() -> std::path::PathBuf {
    env!("CARGO_BIN_EXE_null").into()
}

fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(bin())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn null binary");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn real_peer_without_live_transport_fails_loudly() {
    // Well-formed .onion peer (56 alnum chars), no NULL_LIVE_TRANSPORT.
    let host = "a".repeat(56);
    let peer = format!("null://{host}.onion?k=QUJD");
    let (ok, _, err) = run(&["--peer", &peer]);
    assert!(!ok, "stub dial for a real peer must fail");
    assert!(
        err.contains("NULL_LIVE_TRANSPORT"),
        "must name the fix, got: {err}"
    );
}
