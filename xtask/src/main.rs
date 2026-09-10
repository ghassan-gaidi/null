//! xtask: reproducible-build verification + release chores.

use anyhow::{Context, Result};
use std::path::PathBuf;

fn main() -> Result<()> {
    let task = std::env::args().nth(1).unwrap_or_else(|| "help".into());
    match task.as_str() {
        "repro" => repro(),
        _ => {
            println!("usage: cargo xtask repro [--release]");
            Ok(())
        }
    }
}

/// Rebuild the `null` binary twice and compare SHA256 digests.
/// Deterministic builds are required for SLSA L3 (§9.1).
fn repro() -> Result<()> {
    let out_dir = PathBuf::from("/tmp/null-repro");
    std::fs::create_dir_all(&out_dir).ok();
    let mut hashes = vec![];
    for i in 0..2 {
        let target = out_dir.join(format!("build{i}"));
        std::fs::create_dir_all(&target).ok();
        let status = std::process::Command::new("cargo")
            .args(["build", "--locked", "--bin", "null"])
            .env("CARGO_TARGET_DIR", &target)
            .env("SOURCE_DATE_EPOCH", "0")
            .env("TZ", "UTC")
            .env("LC_ALL", "C")
            .status()
            .context("cargo build")?;
        if !status.success() {
            anyhow::bail!("build {i} failed");
        }
        let bin = target.join("debug/null");
        let bytes = std::fs::read(&bin).with_context(|| format!("read {}", bin.display()))?;
        hashes.push(sha256_hex(&bytes));
    }
    println!("build0: {}", hashes[0]);
    println!("build1: {}", hashes[1]);
    if hashes[0] == hashes[1] {
        println!("REPRODUCIBLE: hashes match");
        Ok(())
    } else {
        anyhow::bail!("NON-REPRODUCIBLE: hashes differ (inspect toolchain/paths)")
    }
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}
