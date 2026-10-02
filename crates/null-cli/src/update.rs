//! Release update CLI (Task 7): `check` verifies a manifest+binary pair
//! against explicit release keys (zero writes); `apply` verifies then
//! installs via temp-file + atomic rename. Distribution (onion fetch,
//! gossip relay) is a documented follow-up — the operator supplies the
//! files; trust comes from signatures, never the transport.
//!
//! Posture: the installed binary is the single deliberate on-disk
//! artifact (explicit `--to`, never implied). Secrets stay RAM-only.

use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use null_update::{UpdateManifest, UpdateStore};

use super::UpdateCmd;

fn flag_or_env(flag: &Option<String>, env: &str, what: &str) -> Result<String> {
    match flag {
        Some(v) => Ok(v.clone()),
        None => std::env::var(env)
            .map_err(|_| anyhow::anyhow!("missing {what}: pass the flag or set {env}")),
    }
}

fn hex_bytes(h: &str, what: &str) -> Result<Vec<u8>> {
    let h = h.trim();
    if h.len() % 2 != 0 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("{what} must be even-length hex");
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|e| anyhow::anyhow!("{what}: {e}")))
        .collect()
}

fn parse_release_vk(hex: &str) -> Result<VerifyingKey> {
    let b = hex_bytes(hex, "--release-vk")?;
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| anyhow::anyhow!("--release-vk must decode to 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| anyhow::anyhow!("bad ed25519 vk: {e}"))
}

fn parse_slh_vk(hex: &str) -> Result<Vec<u8>> {
    let b = hex_bytes(hex, "--release-vk-slh")?;
    if b.len() != 32 {
        anyhow::bail!("--release-vk-slh must decode to 32 bytes (SLH-DSA-SHA2-128s)");
    }
    Ok(b)
}

/// Release binaries are small; refuse absurd inputs before hashing.
const BINARY_MAX_BYTES: usize = 256 * 1024 * 1024;

struct Verified {
    manifest: UpdateManifest,
    binary: Vec<u8>,
}

/// Verify floor → Ed25519 → SLH-DSA → binary SHA3, in that order (the
/// store enforces exactly this). Writes nothing.
fn verify(
    manifest_path: &str,
    binary_path: &str,
    vk_hex: &Option<String>,
    slh_hex: &Option<String>,
    current: &Option<String>,
) -> Result<Verified> {
    let vk = parse_release_vk(&flag_or_env(vk_hex, "NULL_RELEASE_VK", "--release-vk")?)?;
    let slh = parse_slh_vk(&flag_or_env(
        slh_hex,
        "NULL_RELEASE_VK_SLH",
        "--release-vk-slh",
    )?)?;
    let current_version: u64 = flag_or_env(current, "NULL_CURRENT_VERSION", "--current-version")?
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("--current-version must be a u64 shipment number"))?;
    let manifest_bytes =
        std::fs::read(manifest_path).map_err(|e| anyhow::anyhow!("read manifest: {e}"))?;
    let manifest = UpdateManifest::from_bytes(&manifest_bytes)
        .map_err(|e| anyhow::anyhow!("manifest: {e}"))?;
    let binary = std::fs::read(binary_path).map_err(|e| anyhow::anyhow!("read binary: {e}"))?;
    if binary.len() > BINARY_MAX_BYTES {
        anyhow::bail!(
            "binary too large (>{} MiB)",
            BINARY_MAX_BYTES / (1024 * 1024)
        );
    }
    let mut store = UpdateStore::new(vk, slh, current_version);
    store
        .offer(manifest.clone(), &binary)
        .map_err(|e| anyhow::anyhow!("offer rejected: {e}"))?;
    Ok(Verified { manifest, binary })
}

pub async fn dispatch(cmd: UpdateCmd) -> Result<()> {
    match cmd {
        UpdateCmd::Check {
            manifest,
            binary,
            release_vk,
            release_vk_slh,
            current_version,
        } => {
            let v = verify(
                &manifest,
                &binary,
                &release_vk,
                &release_vk_slh,
                &current_version,
            )?;
            println!(
                "OFFER version={} sha3={} lock={}",
                v.manifest.version, v.manifest.sha3_256_hex, v.manifest.cargo_lock_digest_hex
            );
            println!("OK adoptable update verified; nothing written");
        }
        UpdateCmd::Apply {
            manifest,
            binary,
            release_vk,
            release_vk_slh,
            current_version,
            to,
        } => {
            let v = verify(
                &manifest,
                &binary,
                &release_vk,
                &release_vk_slh,
                &current_version,
            )?;
            let to = std::path::PathBuf::from(&to);
            let parent = to
                .parent()
                .ok_or_else(|| anyhow::anyhow!("--to has no parent dir"))?;
            if !parent.is_dir() {
                anyhow::bail!(
                    "target dir does not exist (not created implicitly): {}",
                    parent.display()
                );
            }
            let tmp = parent.join(format!(".null-update-tmp-{}", std::process::id()));
            let cleanup = |e: anyhow::Error| {
                let _ = std::fs::remove_file(&tmp);
                e
            };
            if let Err(e) = (|| -> Result<()> {
                std::fs::write(&tmp, &v.binary).map_err(|e| anyhow::anyhow!("write tmp: {e}"))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
                        .map_err(|e| anyhow::anyhow!("chmod tmp: {e}"))?;
                }
                std::fs::File::open(&tmp)?
                    .sync_all()
                    .map_err(|e| anyhow::anyhow!("fsync tmp: {e}"))?;
                std::fs::rename(&tmp, &to)
                    .map_err(|e| anyhow::anyhow!("rename into place: {e}"))?;
                Ok(())
            })() {
                return Err(cleanup(e));
            }
            println!(
                "installed version={} to={}",
                v.manifest.version,
                to.display()
            );
        }
    }
    Ok(())
}
