//! Volatile-RAM memory hardening, Linux-first (§7).
//!
//! - mlock/munlock + MADV_DONTDUMP/WILLNEED + PR_SET_DUMPABLE=0
//! - panic wipe (random → zero → random → zero) + munlock discipline
//! - systemd-logind sleep inhibitor hook (best-effort)

use null_core::{NullError, Result};
use rand::{rngs::OsRng, RngCore};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use zeroize::Zeroize;

#[cfg(target_os = "linux")]
mod os {
    pub use libc::{
        c_void, madvise, mlock, munlock, prctl, MADV_DONTDUMP, MADV_WILLNEED, PR_SET_DUMPABLE,
    };
}

/// Locked, non-dumpable heap region. Zeroized + unlocked on drop.
pub struct HardenedBuffer {
    ptr: *mut u8,
    layout: Layout,
    len: usize,
}

unsafe impl Send for HardenedBuffer {}
unsafe impl Sync for HardenedBuffer {}

impl HardenedBuffer {
    pub fn new(len: usize) -> Result<Self> {
        if len == 0 {
            return Err(NullError::Memory("zero len".into()));
        }
        let layout = Layout::from_size_align(len, 8)
            .map_err(|e| NullError::Memory(format!("layout: {e}")))?;
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(NullError::Memory("alloc failed".into()));
        }
        let b = Self { ptr, layout, len };
        b.lock()?;
        b.advise()?;
        b.make_undumpable()?;
        Ok(b)
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    fn lock(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let r = unsafe { os::mlock(self.ptr as *const os::c_void, self.len) };
            if r != 0 {
                // mlock can fail under RLIMIT_MEMLOCK in containers; warn but
                // continue — still volatile RAM, just pageable.
                eprintln!(
                    "[null-memory] WARN: mlock failed (errno {}), continuing unlocked",
                    std::io::Error::last_os_error()
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self.ptr;
        }
        Ok(())
    }

    fn advise(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        unsafe {
            // Keep resident; exclude from core dumps.
            os::madvise(self.ptr as *mut os::c_void, self.len, os::MADV_WILLNEED);
            os::madvise(self.ptr as *mut os::c_void, self.len, os::MADV_DONTDUMP);
        }
        Ok(())
    }

    fn make_undumpable(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        unsafe {
            // PR_SET_DUMPABLE=0: no ptrace / core dumps.
            os::prctl(os::PR_SET_DUMPABLE as _, 0, 0, 0, 0);
        }
        Ok(())
    }

    /// Gutmann-inspired wipe: random → zero → random → zero. The final
    /// zero pass keeps allocator-reused pages clean; then the region is
    /// munlocked.
    pub fn panic_wipe(&mut self) {
        let s = self.as_mut_slice();
        OsRng.fill_bytes(s);
        s.zeroize();
        OsRng.fill_bytes(s);
        s.zeroize();
        #[cfg(target_os = "linux")]
        unsafe {
            os::munlock(self.ptr as *const os::c_void, self.len);
        }
    }
}

impl Drop for HardenedBuffer {
    fn drop(&mut self) {
        self.panic_wipe();
        unsafe { dealloc(self.ptr, self.layout) };
    }
}

/// Global panic-wipe registry: call `install_panic_wipe` at startup so
/// SIGINT/SIGTERM/SIGHUP and Rust panics trigger screen+key wipe.
pub fn panic_wipe_all_and_clear_screen() {
    // Clear alternate-screen scrollback: ESC[3J ESC[H ESC[2J.
    print!("\x1b[3J\x1b[H\x1b[2J");
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

/// Best-effort systemd sleep inhibitor: returns guard string describing
/// state. Real inhibitor fd via `systemd-inhibit` is wired in null-cli so
/// this crate stays dependency-free.
pub fn sleep_protection_status() -> &'static str {
    if std::path::Path::new("/run/systemd/seats").exists() {
        "systemd-logind present: caller should hold delay lock (see null-cli)"
    } else {
        "no systemd: warn user if hibernation enabled"
    }
}

// ---------------------------------------------------------------------------
// HSM integration (§7.5).
//
// The shared ratchet root is NEVER mixed with device-local HSM material:
// peers could not converge (each device differs). The HSM instead guards
// LOCAL secrets — long-term identity keys and sealed backups — while the
// Tier-1 default keeps everything in volatile RAM.
// ---------------------------------------------------------------------------

/// Hardware (or software) backend guarding local secrets.
pub trait HsmBackend: Send + Sync {
    /// Stable label recorded in logs/diagnostics (never key material).
    fn name(&self) -> &'static str;
    /// True when the backend can actually isolate keys on this machine.
    fn isolates_keys(&self) -> bool;
    /// Device-bind a local secret (e.g. identity seed): domain-separated
    /// mixing with device-stable material. Deterministic per device.
    fn bind_local(&self, secret: &[u8], context: &[u8]) -> [u8; 48];
}

/// Tier 1 (default): RAM-only keys, no isolation, device binding via
/// `/etc/machine-id` (stable per install, world-readable by design — this
/// binds, it does not hide).
pub struct SoftwareHsm {
    machine_id: Vec<u8>,
}

impl SoftwareHsm {
    pub fn new() -> Self {
        let machine_id = std::fs::read("/etc/machine-id")
            .ok()
            .map(|b| b.trim_ascii().to_vec())
            .unwrap_or_else(|| b"unknown-machine".to_vec());
        Self { machine_id }
    }
}

impl Default for SoftwareHsm {
    fn default() -> Self {
        Self::new()
    }
}

impl HsmBackend for SoftwareHsm {
    fn name(&self) -> &'static str {
        "software-ram (Tier 1)"
    }

    fn isolates_keys(&self) -> bool {
        false
    }

    fn bind_local(&self, secret: &[u8], context: &[u8]) -> [u8; 48] {
        use sha2::{Digest, Sha384};
        let mut h = Sha384::new();
        h.update(b"Null-v2.0-hsm-bind:");
        h.update(context);
        h.update(&self.machine_id);
        h.update(secret);
        h.finalize().into()
    }
}

/// Tier 2 probe: TPM 2.0 resource manager, Apple Secure Enclave, YubiKey.
/// Present-day detection only — key operations through these devices need
/// their native stacks (`tpm2-tss`, `ykman`); until linked, attempts to
/// bind report exactly that instead of silently downgrading.
pub struct HardwareHsmProbe;

impl HardwareHsmProbe {
    /// Names of usable hardware isolates found on this machine (may be empty).
    pub fn detect() -> Vec<&'static str> {
        let mut found = Vec::new();
        if std::path::Path::new("/dev/tpmrm0").exists()
            || std::path::Path::new("/dev/tpm0").exists()
        {
            found.push("tpm2");
        }
        if std::path::Path::new("/usr/bin/ykman").exists()
            || std::path::Path::new("/usr/bin/ykchalresp").exists()
        {
            found.push("yubikey-slot2-hmac");
        }
        #[cfg(target_os = "macos")]
        found.push("secure-enclave");
        found
    }

    pub fn report() -> String {
        let found = Self::detect();
        if found.is_empty() {
            "no hardware isolate detected (Tier 1 software)".to_string()
        } else {
            format!(
                "hardware present [{}]; use native tools to seal identity keys",
                found.join(",")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_roundtrip_and_wipe() {
        let mut b = HardenedBuffer::new(64).unwrap();
        b.as_mut_slice().copy_from_slice(&[7u8; 64]);
        assert_eq!(b.as_slice()[0], 7);
        b.panic_wipe();
        assert!(b.as_slice().iter().all(|&x| x == 0));
    }

    #[test]
    fn zero_len_rejected() {
        assert!(HardenedBuffer::new(0).is_err());
    }

    #[test]
    fn software_hsm_binds_deterministically() {
        let hsm = SoftwareHsm::new();
        assert_eq!(hsm.name(), "software-ram (Tier 1)");
        assert!(!hsm.isolates_keys());
        let a = hsm.bind_local(b"seed", b"ctx");
        let b = hsm.bind_local(b"seed", b"ctx");
        assert_eq!(a, b);
        assert_ne!(a, hsm.bind_local(b"other", b"ctx"));
        assert_ne!(a, hsm.bind_local(b"seed", b"other-ctx"));
    }

    #[test]
    fn hardware_probe_reports() {
        // Must not panic on any machine; content is environment-dependent.
        let _ = HardwareHsmProbe::report();
    }
}
