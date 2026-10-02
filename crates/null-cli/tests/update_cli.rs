//! Update verify/apply through the `null` binary: signed fixtures are
//! built in-test (release keys generated here, never shipped), then
//! `update check` (zero writes) and `update apply` (temp→verify→rename)
//! are driven as an operator would. Tampered/downgraded offers must fail
//! with the install target untouched.

use std::path::PathBuf;
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("null-update-test-{}-{}", std::process::id(), tag));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Build a signed release fixture: (manifest_path, binary_path, vk_hex, slh_hex).
fn fixture(dir: &std::path::Path, version: u64, binary: &[u8]) -> (String, String, String, String) {
    use ed25519_dalek::SigningKey;
    use null_update::{sign_manifest, slh::SlhReleaseKey};
    use rand::rngs::OsRng;

    let sk = SigningKey::generate(&mut OsRng);
    let sk_slh = SlhReleaseKey::generate();
    let m = sign_manifest(&sk, &sk_slh, version, binary, b"lockfile-bytes");
    let mp = dir.join(format!("manifest-{version}.json"));
    let bp = dir.join(format!("binary-{version}.bin"));
    std::fs::write(&mp, m.to_bytes().unwrap()).unwrap();
    std::fs::write(&bp, binary).unwrap();
    (
        mp.to_str().unwrap().to_string(),
        bp.to_str().unwrap().to_string(),
        hex(sk.verifying_key().as_bytes()),
        hex(&sk_slh.verifying_bytes()),
    )
}

#[test]
fn update_check_and_apply_flow() {
    let dir = tmpdir("flow");
    let binary_v3 = b"fake-release-binary-v3";
    let (mp, bp, vk, slh) = fixture(&dir, 3, binary_v3);
    let base = [
        "--manifest",
        &mp,
        "--binary",
        &bp,
        "--release-vk",
        &vk,
        "--release-vk-slh",
        &slh,
        "--current-version",
        "2",
    ];

    // 1. check: valid offer reported, nothing written.
    let mut args = vec!["update", "check"];
    args.extend_from_slice(&base);
    let before: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let (ok, out, err) = run(&args);
    assert!(ok, "check failed: {err}");
    assert!(out.contains("version=3"), "reports version: {out}");
    let after: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(before, after, "check must write nothing");

    // 2. downgrade refused (manifest v2 vs current 2).
    let (mp2, bp2, _, _) = fixture(&dir, 2, b"old-binary");
    let (ok, _, err) = run(&[
        "update",
        "check",
        "--manifest",
        &mp2,
        "--binary",
        &bp2,
        "--release-vk",
        &vk,
        "--release-vk-slh",
        &slh,
        "--current-version",
        "2",
    ]);
    assert!(!ok, "downgrade must fail");
    assert!(err.contains("Downgrade") || err.contains("downgrade") || err.contains("version"));

    // 3. tampered binary refused.
    std::fs::write(&bp, b"tampered-bytes").unwrap();
    let (ok, _, _) = run(&args);
    assert!(!ok, "tampered binary must fail");
    std::fs::write(&bp, binary_v3).unwrap(); // restore

    // 4. apply: verified binary installed atomically.
    let target = dir.join("installed-null").to_str().unwrap().to_string();
    let mut aargs = vec!["update", "apply"];
    aargs.extend_from_slice(&base);
    aargs.extend_from_slice(&["--to", &target]);
    let (ok, out, err) = run(&aargs);
    assert!(ok, "apply failed: {err}");
    assert!(out.contains("installed"), "install report: {out}");
    assert_eq!(std::fs::read(&target).unwrap(), binary_v3);

    // 5. apply of a forged offer fails with the target untouched.
    let mut bad = std::fs::read(&mp).unwrap();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let bad_mp = dir.join("manifest-bad.json").to_str().unwrap().to_string();
    std::fs::write(&bad_mp, &bad).unwrap();
    std::fs::remove_file(&target).unwrap();
    let (ok, _, _) = run(&[
        "update",
        "apply",
        "--manifest",
        &bad_mp,
        "--binary",
        &bp,
        "--release-vk",
        &vk,
        "--release-vk-slh",
        &slh,
        "--current-version",
        "2",
        "--to",
        &target,
    ]);
    assert!(!ok, "forged apply must fail");
    assert!(
        !std::path::Path::new(&target).exists(),
        "target must be untouched"
    );

    // 6. missing trust root fails loudly (no implicit keys).
    let (ok, _, err) = run(&["update", "check", "--manifest", &mp, "--binary", &bp]);
    assert!(!ok, "missing keys must fail: {err}");

    let _ = std::fs::remove_dir_all(&dir);
}
