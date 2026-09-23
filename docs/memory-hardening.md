# Memory & endpoint hardening

Everything that keeps keys out of disk, out of dumps, and out of easy
grasp when a machine (or its owner) is compromised. Implementation:
`crates/null-memory` + hardening reached from `null-cli` and `null-tui`.

## 1. RAM-only, zero disk writes

- No database, no config files, no session logs, no swap-backed key
  storage. `null` writes nothing to disk apart from what the build does.
- Every key container implements `zeroize::ZeroizeOnDrop`; small secrets
  (root/chain/message keys) are derived on the stack where possible and
  wiped when the frame is done (`perf(crypto)`: ratchet keys on the
  stack, no-op Drop removed).
- The skipped-sign chain-key cache (`MAX_SKIP = 200`) and retained rekeys
  (`RETAINED_REKEYS = 8`) live in RAM and are wiped on drop.

## 2. Kernel-backed protections (Linux-first)

- `mlock` pins secret buffers so they never spill to swap.
- `MADV_DONTDUMP` excludes secret regions from core dumps (with
  `MADV_WILLNEED` to keep them resident per the advisory pattern).
- `PR_SET_DUMPABLE = 0` and ptrace hardening: a debugger cannot attach to
  a live `null` without the operator going out of their way.
- macOS/Windows equivalents are scaffolded (`VirtualLock`,
  `mach_vm_wire`) behind the same `MemoryPool` abstraction — the Linux
  path is the tested one.

## 3. The panic wipe

`panic_wipe_all_and_clear_screen` runs on any of:

- SIGINT (Ctrl-C), SIGTERM, SIGHUP (signal_hook handlers),
- the Rust panic hook (clears the screen before unwinding),
- `/quit`, stdin EOF, peer goodbye, peer FIN/RST,
- the dead-man switch,
- the USBGuard trigger (new `/dev` node).

Sequence: disable re-entry → overwrite all key buffers with CSPRNG
random → overwrite with zeros → random again (3-pass) → unlock/munmap →
clear the terminal (alternate-screen exit, scrollback kill) → `exit 0`.
Deliberate exits are **always 0 after a wipe**; error paths propagate a
nonzero status before the wipe runs.

## 4. Terminal hygiene

- Enters the alternate screen on startup, disables scrollback/selection
  history where the terminal permits, and kills scrollback on exit.
- Although it reads input from `/dev/tty` (not stdin history), real
  terminal keyloggers are a stated mitigation-only problem — see
  `--secure-input` below.
- Bracketed paste stays off by default; the TUI prompts explicitly when a
  paste is offered.

## 5. Clipboard sanitization

- A copy (`/copy` or TUI copy action) schedules a background clear after
  `CLIPBOARD_CLEAR_SECS` seconds (**5**), on `wl-copy`/`xclip`/
  `pbcopy`/`termux` families per OS.
- Wayland `wl-copy` zombies are reaped (fixed); the clear thread exists so
  the UI never blocks on it.
- Clipboard-manager presence is detected and the user is warned (a manager
  like CopyQ/Ditto defeats any app-level clear).

## 6. Secure input (`--secure-input`)

- Root-only: grabs `/dev/input/event*` via a minimal evdev keymap and
  reads keystrokes directly, bypassing terminal keyloggers
  (`null-cli/src/secure_input.rs`).
- Without root it warns and falls back to `/dev/tty`; in TUI mode it is
  ignored (the TUI owns the keyboard) with a warning.
- Fallback cadence: 1 s retry on read errors.

## 7. Duress, decoy, lock, dead-man, USBGuard

| Feature | Default | Behavior |
|---|---|---|
| Auto-lock (`--auto-lock-secs`) | 1800 s (30 min) idle | Blurs/locks the UI; PIN to resume |
| Dead-man switch (`--dead-man-secs`) | **Disabled (0)** — the code-level baseline constant is `DEAD_MAN_SWITCH_SECS = 1800`, but shipping it armed by default would wipe laptops on idle; enabling is an explicit operator decision | Wipe keys + exit after N idle seconds |
| Duress PIN | TUI demo PIN `1234`, duress `0000` | Wrong-PIN path wipes keys, shows a plausible "disconnected" state |
| Decoy mode (`--safe`) | off | Benign IRC-like interface; the real session hides behind `/unlock` |
| USBGuard (`--usbguard`) | off | Polls `/dev`; any new node → panic wipe + exit 0 |

## 8. HSM tiers

- **Tier 1 — software, shipped**: `SoftwareHsm::bind_local(secret,
  context) = SHA384("Null-v2.0-hsm-bind:" ‖ context ‖ machine_id ‖
  secret)`, machine id from `/etc/machine-id`. Device-bound local *identity
  material* only.
- **Critical rule**: the *shared ratchet root* is **never** mixed with
  device-local material — peers could not converge on a session key.
  Device binding guards local secrets (identities, device ids), and the
  handshake/ratchet root is derived purely from protocol material.
- **Tier 2 — probe (`--hsm check`)**: detects TPM2 (`/dev/tpmrm0`,
  `/dev/tpm0` → `tpm2`), YubiKey (`ykman`/`ykchalresp` →
  `yubikey-slot2-hmac`), and macOS Secure Enclave. Detection reports
  honestly instead of silently downgrading; **native key operations need
  the vendor stacks (tpm2-tss, ykman, SE SDK), which are not yet linked**
  (`docs/security-posture.md`).

## 9. Sleep / hibernation

`sleep_protection_status()` reports whether the OS will write RAM to disk
before suspend (systemd-logind inhibitor logic on Linux; macOS/Windows
hooks scaffolded). The CLI prints this at startup so an operator running
`null` on a laptop sees the hibernation risk before it matters. Inline
pre-suspend wiping is roadmap work.

## 10. Threat-model honesty

These are **mitigations, not proofs**:

- A live-process memory scraper (user-level malware already running)
  wins; anti-dump/`mlock` only raise the bar (`docs/threat-model.md`).
- Root/kernel malware is out of scope for any messenger.
- Cold boot with power retained is made expensive (RAM-only, wipe on
  signal), not impossible.
- TPM/YubiKey/Secure Enclave *operations* are not shipped; the probe
  cannot be relied on as a key-isolation boundary today.