//! Device roster over pipes: enroll → list/active → member-id →
//! revoke, all through the `null` binary. Gives DeviceSet a production
//! consumer (roster management for operators driving group add/remove);
//! carries no secrets (eks are public).

use std::collections::HashMap;
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

fn labeled(stdout: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for line in stdout.lines() {
        if let Some((k, v)) = line.split_once(':') {
            m.insert(k.to_string(), v.to_string());
        }
    }
    m
}

const DEV_A: &str = "11111111111111111111111111111111";
const DEV_B: &str = "22222222222222222222222222222222";

#[test]
fn devices_roster_pipe_flow() {
    // 1. Fresh enroll (fp required without --set).
    let (ok, out, err) = run(&[
        "devices",
        "enroll",
        "--fp",
        "ml-dsa:testfp",
        "--device",
        DEV_A,
        "--ek",
        "ZWsx",
    ]);
    assert!(ok, "enroll failed: {err}");
    let s0 = labeled(&out);
    assert!(!s0["SET"].is_empty());

    // 2. Second device into the existing set.
    let (ok, out, err) = run(&[
        "devices", "enroll", "--set", &s0["SET"], "--device", DEV_B, "--ek", "ZWsy",
    ]);
    assert!(ok, "enroll 2 failed: {err}");
    let s1 = labeled(&out);

    // 3. list shows both; active is the fan-out set.
    let (ok, out, err) = run(&["devices", "list", "--set", &s1["SET"]]);
    assert!(ok, "list failed: {err}");
    assert_eq!(out.lines().count(), 2, "two devices: {out}");
    let (ok, out, err) = run(&["devices", "active", "--set", &s1["SET"]]);
    assert!(ok, "active failed: {err}");
    assert_eq!(out.lines().count(), 2, "two active: {out}");

    // 4. member-id is deterministic per (fp, device).
    let mid = |fp: &str, dev: &str| {
        let (ok, out, err) = run(&["devices", "member-id", "--fp", fp, "--device", dev]);
        assert!(ok, "member-id failed: {err}");
        labeled(&out)["MEMBER"].clone()
    };
    let m_a1 = mid("ml-dsa:testfp", DEV_A);
    assert_eq!(m_a1.len(), 64);
    assert_eq!(mid("ml-dsa:testfp", DEV_A), m_a1, "stable");
    assert_ne!(mid("ml-dsa:testfp", DEV_B), m_a1, "per-device");
    assert_ne!(mid("ml-dsa:other", DEV_A), m_a1, "identity-bound");

    // 5. Revoke shrinks the fan-out set; double/unknown revoke are loud.
    let (ok, out, err) = run(&["devices", "revoke", "--set", &s1["SET"], "--device", DEV_A]);
    assert!(ok, "revoke failed: {err}");
    let s2 = labeled(&out);
    let (ok, out, err) = run(&["devices", "active", "--set", &s2["SET"]]);
    assert!(ok, "active failed: {err}");
    assert_eq!(out.lines().count(), 1, "one active left: {out}");
    assert!(out.contains(DEV_B));
    let (ok, _, _) = run(&["devices", "revoke", "--set", &s2["SET"], "--device", DEV_A]);
    assert!(!ok, "double revoke must fail");
    let (ok, _, _) = run(&[
        "devices",
        "revoke",
        "--set",
        &s2["SET"],
        "--device",
        "99999999999999999999999999999999",
    ]);
    assert!(!ok, "unknown revoke must fail");

    // 6. fp mismatch and garbage fail loudly.
    let (ok, _, _) = run(&[
        "devices",
        "enroll",
        "--set",
        &s2["SET"],
        "--fp",
        "ml-dsa:wrong",
        "--device",
        DEV_A,
        "--ek",
        "ZWsx",
    ]);
    assert!(!ok, "fp mismatch must fail");
    let (ok, _, _) = run(&["devices", "list", "--set", "!!!not-base64!!!"]);
    assert!(!ok, "garbage set must fail");
    let (ok, _, _) = run(&["devices", "enroll", "--device", DEV_A, "--ek", "ZWsx"]);
    assert!(!ok, "fresh enroll needs --fp");
}
