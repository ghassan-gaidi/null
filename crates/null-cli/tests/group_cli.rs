//! Group membership over pipes: keygen → create → add → join →
//! info/roster → sync → remove → update, all through the `null` binary
//! with base64 blobs on stdio. Proves pipe continuity (state codec +
//! verbs) across processes — the production consumer for null-group.

use std::collections::HashMap;
use std::process::{Command, Stdio};

fn bin() -> std::path::PathBuf {
    env!("CARGO_BIN_EXE_null").into()
}

/// Run the binary; return (success, stdout). Stderr is captured for
/// failure context only.
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

/// Run with a blob on stdin (no --state arg).
fn run_stdin(args: &[&str], input: &str) -> (bool, String, String) {
    use std::io::Write;
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn null binary");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}
/// Parse `LABEL:payload` lines into a map (last wins).
fn labeled(stdout: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for line in stdout.lines() {
        if let Some((k, v)) = line.split_once(':') {
            m.insert(k.to_string(), v.to_string());
        }
    }
    m
}

#[test]
fn group_membership_pipe_flow() {
    // 1. keygen: joiner identity material.
    let (ok, out, err) = run(&["group", "keygen"]);
    assert!(ok, "keygen failed: {err}");
    let kg = labeled(&out);
    assert!(kg["MEMBER"].len() == 64, "member id hex");
    assert!(!kg["KEYPACKAGE"].is_empty());
    assert!(!kg["DK"].is_empty());

    // 2. create: fresh one-member group.
    let (ok, out, err) = run(&["group", "create"]);
    assert!(ok, "create failed: {err}");
    let c0 = labeled(&out);
    assert!(!c0["STATE"].is_empty());

    // 3. add: joiner enters; commit + welcome + advanced state out.
    let (ok, out, err) = run(&[
        "group",
        "add",
        "--state",
        &c0["STATE"],
        "--keypackage",
        &kg["KEYPACKAGE"],
    ]);
    assert!(ok, "add failed: {err}");
    let a1 = labeled(&out);
    assert!(!a1["COMMIT"].is_empty());
    assert!(!a1["WELCOME"].is_empty());
    assert!(!a1["STATE"].is_empty());
    assert_ne!(a1["STATE"], c0["STATE"], "state must advance");

    // 4. join: joiner adopts state from the welcome.
    let (ok, out, err) = run(&[
        "group",
        "join",
        "--welcome",
        &a1["WELCOME"],
        "--keypackage",
        &kg["KEYPACKAGE"],
        "--dk",
        &kg["DK"],
        "--member-id",
        &kg["MEMBER"],
    ]);
    assert!(ok, "join failed: {err}");
    let j = labeled(&out);
    assert!(!j["STATE"].is_empty());

    // 5. info/roster: two members, same epoch on both copies.
    let (ok, out, err) = run(&["group", "info", "--state", &a1["STATE"]]);
    assert!(ok, "info failed: {err}");
    assert!(out.contains("members=2"), "two members: {out}");
    let (ok, out, err) = run(&["group", "roster", "--state", &a1["STATE"]]);
    assert!(ok, "roster failed: {err}");
    assert_eq!(out.lines().count(), 2, "two roster lines: {out}");

    // 6. update: creator rotates; joiner ingests via sync.
    let (ok, out, err) = run(&["group", "update", "--state", &a1["STATE"]]);
    assert!(ok, "update failed: {err}");
    let u = labeled(&out);
    let (ok, out, err) = run(&[
        "group",
        "sync",
        "--state",
        &j["STATE"],
        "--commit",
        &u["COMMIT"],
    ]);
    assert!(ok, "sync failed: {err}");
    let s = labeled(&out);
    let epoch_of = |state: &str| {
        let (ok, out, err) = run(&["group", "info", "--state", state]);
        assert!(ok, "info failed: {err}");
        out.lines()
            .find(|l| l.starts_with("INFO "))
            .expect("INFO line")
            .to_string()
    };
    assert_eq!(
        epoch_of(&u["STATE"]),
        epoch_of(&s["STATE"]),
        "epochs converge"
    );

    // 7. remove: joiner leaves; creator back to one member.
    let (ok, out, err) = run(&[
        "group",
        "remove",
        "--state",
        &u["STATE"],
        "--member-id",
        &kg["MEMBER"],
    ]);
    assert!(ok, "remove failed: {err}");
    let r = labeled(&out);
    let (ok, out, err) = run(&["group", "info", "--state", &r["STATE"]]);
    assert!(ok, "info failed: {err}");
    assert!(out.contains("members=1"), "one member left: {out}");

    // 8. Bad inputs fail loudly (nonzero exit), never silently.
    let (ok, _, _) = run(&["group", "info", "--state", "!!!not-base64!!!"]);
    assert!(!ok, "garbage state must fail");
    let (ok, _, _) = run(&[
        "group",
        "remove",
        "--state",
        &r["STATE"],
        "--member-id",
        "xyz",
    ]);
    assert!(!ok, "bad member id must fail");

    // 9. Single-blob verbs read stdin when --state is absent.
    let (ok, out, err) = run_stdin(&["group", "info"], &r["STATE"]);
    assert!(ok, "stdin info failed: {err}");
    assert!(out.contains("members=1"), "stdin state works: {out}");
}
