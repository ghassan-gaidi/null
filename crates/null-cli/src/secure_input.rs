//! Secure input (§8.3): read keystrokes straight from Linux evdev
//! (`/dev/input/event*`) to bypass terminal keyloggers. Needs root; any
//! failure falls back to `/dev/tty` with a warning. US layout.

use std::io::Read;
use std::os::unix::fs::FileTypeExt;

// linux/input-event-codes.h (subset).
const EV_KEY: u16 = 0x01;
const KEY_BACKSPACE: u16 = 14;
const KEY_ENTER: u16 = 28;
const KEY_SPACE: u16 = 57;
const KEY_LEFTSHIFT: u16 = 42;
const KEY_RIGHTSHIFT: u16 = 54;

/// True when we could plausibly grab a keyboard (root + evdev present).
pub fn available() -> bool {
    super::is_root() && first_keyboard().is_some()
}

/// Scan `/dev/input` for the first char device advertising EV_KEY.
pub fn first_keyboard() -> Option<std::path::PathBuf> {
    keyboard_in("/dev/input")
}

fn keyboard_in(dir: &str) -> Option<std::path::PathBuf> {
    let rd = std::fs::read_dir(dir).ok()?;
    let mut cands: Vec<_> = rd
        .filter_map(|e| e.ok().map(|d| d.path()))
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().starts_with("event"))
                .unwrap_or(false)
        })
        .collect();
    cands.sort();
    cands.into_iter().find(|p| {
        std::fs::metadata(p)
            .map(|m| m.file_type().is_char_device())
            .unwrap_or(false)
            && has_ev_key(p)
    })
}

/// EVIOCGBIT(EV_KEY) probe: does this device emit keys at all?
fn has_ev_key(path: &std::path::Path) -> bool {
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut bits = [0u8; 8];
    if eviocgbit(&f, EV_KEY as u32, &mut bits).is_err() {
        return false;
    }
    // EV_KEY bitset covers codes 0..63 here; any key bit = keyboard-ish.
    bits.iter().any(|&b| b != 0)
}

fn eviocgbit(f: &std::fs::File, ev: u32, buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // _IOR('E', 0x20+ev, len)
    let req = (2u64 << 30) | ((b'E' as u64) << 8) | (0x20 + ev as u64) | ((buf.len() as u64) << 16);
    let r = unsafe {
        libc::ioctl(
            f.as_raw_fd(),
            req as libc::c_ulong,
            buf.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Grab the keyboard exclusively and read one line (Enter-terminated).
/// Echoes to stderr so chat stays usable. Releases the grab on return.
pub fn read_line_grabbed() -> std::io::Result<String> {
    use std::os::unix::io::AsRawFd;
    let path = first_keyboard()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no keyboard"))?;
    let f = std::fs::OpenOptions::new().read(true).open(&path)?;
    // EVIOCGRAB = _IOW('E', 0x90, int)
    let grab: libc::c_ulong = ((1u64 << 30) | ((b'E' as u64) << 8) | 0x90 | ((4u64) << 16)) as _;
    let one: libc::c_int = 1;
    unsafe {
        libc::ioctl(f.as_raw_fd(), grab, &one as *const _ as *const libc::c_void);
    }
    let res = read_line_from(&f);
    let zero: libc::c_int = 0;
    unsafe {
        libc::ioctl(
            f.as_raw_fd(),
            grab,
            &zero as *const _ as *const libc::c_void,
        );
    }
    res
}

fn read_line_from(mut f: &std::fs::File) -> std::io::Result<String> {
    use std::io::Write;
    let mut out = String::new();
    let mut shift = false;
    let mut ev = [0u8; 24];
    loop {
        f.read_exact(&mut ev)?;
        let typ = u16::from_ne_bytes([ev[16], ev[17]]);
        let code = u16::from_ne_bytes([ev[18], ev[19]]);
        let value = i32::from_ne_bytes([ev[20], ev[21], ev[22], ev[23]]);
        if typ != EV_KEY {
            continue;
        }
        if code == KEY_LEFTSHIFT || code == KEY_RIGHTSHIFT {
            shift = value != 0;
            continue;
        }
        if value == 0 {
            continue; // release
        }
        match code {
            KEY_ENTER => {
                eprintln!();
                return Ok(out);
            }
            KEY_BACKSPACE => {
                out.pop();
                let _ = write!(std::io::stderr(), "\x08 \x08");
                let _ = std::io::stderr().flush();
            }
            KEY_SPACE => {
                out.push(' ');
                let _ = write!(std::io::stderr(), " ");
                let _ = std::io::stderr().flush();
            }
            c => {
                if let Some(ch) = map_key(c, shift) {
                    out.push(ch);
                    let _ = write!(std::io::stderr(), "{ch}");
                    let _ = std::io::stderr().flush();
                }
            }
        }
    }
}

/// US-layout scancode → char (None = unmapped).
pub fn map_key(code: u16, shift: bool) -> Option<char> {
    // Letters: QWERTY row order by scancode.
    const LETTERS: &[(u16, char)] = &[
        (16, 'q'),
        (17, 'w'),
        (18, 'e'),
        (19, 'r'),
        (20, 't'),
        (21, 'y'),
        (22, 'u'),
        (23, 'i'),
        (24, 'o'),
        (25, 'p'),
        (30, 'a'),
        (31, 's'),
        (32, 'd'),
        (33, 'f'),
        (34, 'g'),
        (35, 'h'),
        (36, 'j'),
        (37, 'k'),
        (38, 'l'),
        (44, 'z'),
        (45, 'x'),
        (46, 'c'),
        (47, 'v'),
        (48, 'b'),
        (49, 'n'),
        (50, 'm'),
    ];
    if let Some((_, base)) = LETTERS.iter().find(|(c, _)| *c == code) {
        return Some(if shift {
            base.to_ascii_uppercase()
        } else {
            *base
        });
    }
    const DIGITS: &[char] = &['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'];
    const SHIFTED_DIGITS: &[char] = &['!', '@', '#', '$', '%', '^', '&', '*', '(', ')'];
    if (2..=11).contains(&code) {
        let i = (code - 2) as usize;
        return Some(if shift { SHIFTED_DIGITS[i] } else { DIGITS[i] });
    }
    let plain: &[(u16, char, char)] = &[
        (12, '-', '_'),
        (13, '=', '+'),
        (26, '[', '{'),
        (27, ']', '}'),
        (39, ';', ':'),
        (40, '\'', '"'),
        (41, '`', '~'),
        (43, '\\', '|'),
        (51, ',', '<'),
        (52, '.', '>'),
        (53, '/', '?'),
    ];
    plain
        .iter()
        .find(|(c, _, _)| *c == code)
        .map(|(_, lo, hi)| if shift { *hi } else { *lo })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keymap_letters_digits_symbols() {
        assert_eq!(map_key(30, false), Some('a'));
        assert_eq!(map_key(30, true), Some('A'));
        assert_eq!(map_key(48, false), Some('b'));
        assert_eq!(map_key(2, false), Some('1'));
        assert_eq!(map_key(2, true), Some('!'));
        assert_eq!(map_key(11, false), Some('0'));
        assert_eq!(map_key(53, false), Some('/'));
        assert_eq!(map_key(12, true), Some('_'));
        assert_eq!(map_key(999, false), None);
        // Enter/space/shift handled by the reader, not the map.
        assert_eq!(map_key(KEY_ENTER, false), None);
    }

    #[test]
    fn device_scan_never_panics() {
        // Environment-dependent; must only not panic or fabricate.
        let _ = keyboard_in("/dev/input");
        let _ = keyboard_in("/nonexistent-dir-xyz");
        assert!(!super::available() || crate::is_root());
    }
}
