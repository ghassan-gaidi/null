//! Terminal interface (§8): Ratatui + Crossterm, alternate screen,
//! anti-scrollback, duress/decoy, auto-lock, clipboard sanitization.

use crossterm::event::{KeyCode, KeyModifiers};
use null_core::CLIPBOARD_CLEAR_SECS;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

/// TUI lifecycle state.
pub struct Tui {
    pub locked: bool,
    pub decoy: bool,
    pub last_activity: Instant,
    pub auto_lock_after: Duration,
}

impl Tui {
    pub fn new(decoy: bool, auto_lock_secs: u64) -> Self {
        Self {
            locked: false,
            decoy,
            last_activity: Instant::now(),
            auto_lock_after: Duration::from_secs(auto_lock_secs),
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn should_auto_lock(&self) -> bool {
        !self.locked && self.last_activity.elapsed() >= self.auto_lock_after
    }

    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Returns true iff PIN correct.
    pub fn unlock(&mut self, pin: &str, real_pin: &str, duress_pin: &str) -> UnlockOutcome {
        if pin == real_pin {
            self.locked = false;
            self.touch();
            UnlockOutcome::Unlocked
        } else if pin == duress_pin {
            UnlockOutcome::DuressTriggered
        } else {
            UnlockOutcome::Denied
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnlockOutcome {
    Unlocked,
    Denied,
    DuressTriggered,
}

/// What the event loop must do after [`App::handle_key`].
#[derive(Debug, PartialEq, Eq)]
pub enum AppAction {
    None,
    Quit,
    /// Panic-wipe and exit (Ctrl-C or duress PIN).
    Wipe,
    /// Encrypt + transmit this line.
    Send(String),
    /// Copy this text (caller schedules the 5s clear).
    Copy(String),
}

/// A composed input line, classified.
#[derive(Debug, PartialEq, Eq)]
pub enum LineCmd {
    Quit,
    Lock,
    Copy,
    Empty,
    Send(String),
}

/// Enter alternate screen + disable scrollback (`?1049h`), hide cursor.
pub fn enter_secure_screen(w: &mut impl Write) -> io::Result<()> {
    write!(w, "\x1b[?1049h\x1b[?47l\x1b[?25l")?;
    w.flush()
}

/// Leave alternate screen, clear scrollback (`3J`), restore cursor.
pub fn leave_secure_screen(w: &mut impl Write) -> io::Result<()> {
    write!(w, "\x1b[3J\x1b[H\x1b[2J\x1b[?1049l\x1b[?25h")?;
    w.flush()
}

/// Best-effort clipboard clear (Linux: xclip/wl-copy/termux; macOS: pbcopy).
/// Auto-invoked 5s after any copy op (§8.2).
pub fn clear_clipboard() {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xclip")
            .args(["-selection", "clipboard", "/dev/null"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = std::process::Command::new("wl-copy")
            .args(["--clear"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("sh")
            .arg("-c")
            .arg("echo -n '' | pbcopy")
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "echo.|clip"])
            .status();
    }
}

/// Copy text to the system clipboard, then schedule an auto-clear after
/// [`CLIPBOARD_CLEAR_SECS`] (§8.2). The clear runs on a background thread so
/// callers never block the chat loop. Each copy bumps a generation counter;
/// only the newest copy's clearer may wipe, so a slower older clearer can
/// never cut a newer copy's 5-second window short.
pub fn clipboard_copy_and_schedule_clear(text: &str) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CLIPBOARD_GEN: AtomicU64 = AtomicU64::new(0);

    copy_to_clipboard(text);
    if let Some(warn) = clipboard_manager_warning() {
        eprintln!("[null] WARN: {warn}");
    }
    let gen = CLIPBOARD_GEN.fetch_add(1, Ordering::SeqCst) + 1;
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(CLIPBOARD_CLEAR_SECS));
        if CLIPBOARD_GEN.load(Ordering::SeqCst) == gen {
            clear_clipboard();
        }
    });
}

fn copy_to_clipboard(text: &str) {
    use std::io::Write;
    #[cfg(target_os = "linux")]
    {
        // Prefer Wayland, fall back to X11.
        let wl = std::process::Command::new("wl-copy")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok();
        if let Some(mut child) = wl {
            let written = child
                .stdin
                .as_mut()
                .map(|s| s.write_all(text.as_bytes()).is_ok())
                .unwrap_or(false);
            if written {
                let _ = child.wait();
                return;
            }
            // wl-copy died before accepting input: reap it (no zombie)
            // before falling back to xclip.
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Ok(mut child) = std::process::Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            if let Some(s) = child.stdin.as_mut() {
                let _ = s.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(mut child) = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(s) = child.stdin.as_mut() {
                let _ = s.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(mut child) = std::process::Command::new("clip")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(s) = child.stdin.as_mut() {
                let _ = s.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = text;
    }
}

/// Detect clipboard managers that defeat auto-clear (CopyQ, Ditto, etc.).
pub fn clipboard_manager_warning() -> Option<String> {
    for proc in ["copyq", "ditto", "clipman", "gpaste"] {
        if std::path::Path::new(&format!("/usr/bin/{proc}")).exists() {
            return Some(format!(
                "clipboard manager `{proc}` detected: history may retain secrets"
            ));
        }
    }
    None
}

/// Render the main chat layout description (line-mode hint).
/// The full-screen [`App`] below is the Ratatui interface.
pub fn layout_hint(decoy: bool) -> &'static str {
    if decoy {
        "IRC-like decoy — type PIN + Enter to reveal session"
    } else {
        "peers | messages | input — /lock /copy /quit"
    }
}

/// Full-screen Ratatui chat application state.
///
/// Pure logic (no terminal handle): push/decrypt events in, render out.
/// The caller owns key exchange; `App` never sees key material.
pub struct App {
    pub tui: Tui,
    pub peer_label: String,
    pub transport_label: String,
    messages: Vec<(String, String)>,
    input: String,
    scroll: usize,
    notice: Option<String>,
    safety: Option<String>,
}

impl App {
    pub fn new(
        peer_label: String,
        transport_label: String,
        decoy: bool,
        auto_lock_secs: u64,
    ) -> Self {
        Self {
            tui: Tui::new(decoy, auto_lock_secs),
            peer_label,
            transport_label,
            messages: Vec::new(),
            input: String::new(),
            scroll: 0,
            notice: None,
            safety: None,
        }
    }

    pub fn push_message(&mut self, author: &str, text: &str) {
        self.messages.push((author.to_string(), text.to_string()));
        self.tui.touch();
    }

    pub fn push_input(&mut self, c: char) {
        // Accepted while locked too: the lock screen needs PIN entry.
        self.input.push(c);
        self.tui.touch();
    }

    pub fn pop_input(&mut self) {
        self.input.pop();
        self.tui.touch();
    }

    /// Take the composed line, leaving the box empty.
    pub fn take_input(&mut self) -> String {
        self.tui.touch();
        std::mem::take(&mut self.input)
    }

    pub fn input(&self) -> &str {
        &self.input
    }

    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    pub fn last_message(&self) -> Option<(&str, &str)> {
        self.messages.last().map(|(a, t)| (a.as_str(), t.as_str()))
    }

    pub fn set_notice(&mut self, notice: impl Into<String>) {
        self.notice = Some(notice.into());
    }

    pub fn set_safety(&mut self, safety: impl Into<String>) {
        self.safety = Some(safety.into());
    }

    pub fn poll_auto_lock(&mut self) {
        if self.tui.should_auto_lock() {
            self.tui.lock();
            self.set_notice("auto-locked (idle) — type PIN + Enter");
        }
    }

    /// Handle a composed line while locked: real PIN unlocks, duress PIN
    /// signals wipe upstream, anything else is denied.
    pub fn unlock_line(&mut self, line: &str, real_pin: &str, duress_pin: &str) -> UnlockOutcome {
        let out = self.tui.unlock(line, real_pin, duress_pin);
        match out {
            UnlockOutcome::Unlocked => self.set_notice("unlocked"),
            UnlockOutcome::Denied => self.set_notice("denied"),
            UnlockOutcome::DuressTriggered => self.set_notice("duress — wiping"),
        }
        out
    }

    /// Interpret a composed input line (unlocked mode).
    pub fn interpret_line(cmd: &str) -> LineCmd {
        match cmd {
            "/quit" => LineCmd::Quit,
            "/lock" => LineCmd::Lock,
            "/copy" => LineCmd::Copy,
            "" => LineCmd::Empty,
            text => LineCmd::Send(text.to_string()),
        }
    }

    /// Route one crossterm key event. Returns the action the caller must
    /// perform (send bytes, wipe, quit, …). PIN entry works while locked;
    /// text entry does not send while locked.
    pub fn handle_key(&mut self, code: KeyCode, mods: KeyModifiers) -> AppAction {
        if mods.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
            return AppAction::Wipe;
        }
        match code {
            KeyCode::Esc => AppAction::Quit,
            KeyCode::Backspace => {
                self.pop_input();
                AppAction::None
            }
            KeyCode::Enter => {
                let line = self.take_input();
                if self.tui.locked {
                    // Demo PINs mirror the CLI help text.
                    return match self.unlock_line(&line, "1234", "0000") {
                        UnlockOutcome::DuressTriggered => AppAction::Wipe,
                        _ => AppAction::None,
                    };
                }
                match Self::interpret_line(line.trim()) {
                    LineCmd::Quit => AppAction::Quit,
                    LineCmd::Lock => {
                        self.tui.lock();
                        self.set_notice("locked — demo PIN is 1234");
                        AppAction::None
                    }
                    LineCmd::Copy => match self.last_message() {
                        Some((_, t)) => AppAction::Copy(t.to_string()),
                        None => {
                            self.set_notice("nothing to copy yet");
                            AppAction::None
                        }
                    },
                    LineCmd::Empty => AppAction::None,
                    LineCmd::Send(text) => AppAction::Send(text),
                }
            }
            KeyCode::Char(c) => {
                self.push_input(c);
                AppAction::None
            }
            _ => AppAction::None,
        }
    }

    /// Render one frame: header / messages / input / footer, or the lock or
    /// decoy screen when those modes are active (§8.4).
    pub fn render(&self, frame: &mut Frame) {
        if self.tui.locked {
            let p = Paragraph::new("LOCKED — type PIN + Enter\n(duress PIN wipes keys)")
                .block(Block::default().borders(Borders::ALL).title("Null"));
            frame.render_widget(p, frame.area());
            return;
        }
        if self.tui.decoy {
            let p = Paragraph::new(
                "#general  [alice] anyone up for chess?\n\
                 #general  [bob]   sure, 5 min\n\
                 — decoy channel (/unlock reveals session) —",
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("null-irc (decoy)"),
            );
            frame.render_widget(p, frame.area());
            return;
        }
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(4),
                Constraint::Length(3),
                Constraint::Length(4),
            ])
            .split(frame.area());
        let header = format!("peer: {} | via: {}", self.peer_label, self.transport_label);
        frame.render_widget(
            Paragraph::new(header).block(Block::default().borders(Borders::ALL).title("Null")),
            chunks[0],
        );
        let items: Vec<ListItem> = self
            .messages
            .iter()
            .skip(self.scroll)
            .map(|(a, t)| ListItem::new(format!("[{a}] {t}")))
            .collect();
        frame.render_widget(
            List::new(items).block(Block::default().borders(Borders::ALL).title("messages")),
            chunks[1],
        );
        frame.render_widget(
            Paragraph::new(self.input.as_str())
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title("input")),
            chunks[2],
        );
        let mut footer = String::from("Enter send · /lock · /quit · /copy");
        if let Some(n) = &self.notice {
            footer.push_str(&format!(" · {n}"));
        }
        if let Some(s) = &self.safety {
            footer.push_str(&format!("\nsafety: {s}"));
        }
        frame.render_widget(
            Paragraph::new(footer).block(Block::default().borders(Borders::ALL)),
            chunks[3],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_unlock_flow() {
        let mut t = Tui::new(false, 60);
        t.lock();
        assert_eq!(t.unlock("real", "real", "duress"), UnlockOutcome::Unlocked);
        assert!(!t.locked);
        t.lock();
        assert_eq!(
            t.unlock("duress", "real", "duress"),
            UnlockOutcome::DuressTriggered
        );
        assert_eq!(t.unlock("nope", "real", "duress"), UnlockOutcome::Denied);
    }

    #[test]
    fn secure_screen_bytes() {
        let mut buf = vec![];
        enter_secure_screen(&mut buf).unwrap();
        assert!(buf.windows(6).any(|w| w == b"?1049h"));
        buf.clear();
        leave_secure_screen(&mut buf).unwrap();
        assert!(buf.windows(2).any(|w| w == b"3J"));
    }

    #[test]
    fn app_input_and_messages() {
        let mut app = App::new("bob".into(), "tor".into(), false, 60);
        app.push_input('h');
        app.push_input('i');
        assert_eq!(app.input(), "hi");
        assert_eq!(app.take_input(), "hi");
        assert_eq!(app.input(), "");
        app.push_message("bob", "hello");
        assert_eq!(app.message_count(), 1);
        assert_eq!(app.last_message(), Some(("bob", "hello")));
        app.pop_input();
    }

    #[test]
    fn app_lock_blocks_input_and_reports() {
        use crossterm::event::{KeyCode, KeyModifiers};
        let mut app = App::new("bob".into(), "tor".into(), false, 60);
        app.tui.lock();
        // Locked: chars still enter the box (PIN entry), Enter routes to unlock.
        assert_eq!(
            app.handle_key(KeyCode::Char('n'), KeyModifiers::empty()),
            AppAction::None
        );
        assert_eq!(
            app.handle_key(KeyCode::Char('o'), KeyModifiers::empty()),
            AppAction::None
        );
        assert_eq!(
            app.handle_key(KeyCode::Char('p'), KeyModifiers::empty()),
            AppAction::None
        );
        assert_eq!(
            app.handle_key(KeyCode::Char('e'), KeyModifiers::empty()),
            AppAction::None
        );
        assert_eq!(
            app.handle_key(KeyCode::Enter, KeyModifiers::empty()),
            AppAction::None
        );
        assert!(app.tui.locked, "wrong PIN keeps lock");
        for c in "1234".chars() {
            app.handle_key(KeyCode::Char(c), KeyModifiers::empty());
        }
        assert_eq!(
            app.handle_key(KeyCode::Enter, KeyModifiers::empty()),
            AppAction::None
        );
        assert!(!app.tui.locked, "demo PIN unlocks");
    }

    #[test]
    fn app_key_routing() {
        use crossterm::event::{KeyCode, KeyModifiers};
        let mut app = App::new("bob".into(), "tor".into(), false, 60);
        // Ctrl-C is reported as lowercase 'c' + CONTROL (no Shift).
        assert_eq!(
            app.handle_key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            AppAction::Wipe
        );
        assert_eq!(
            app.handle_key(KeyCode::Esc, KeyModifiers::empty()),
            AppAction::Quit
        );
        for c in "/quit".chars() {
            app.handle_key(KeyCode::Char(c), KeyModifiers::empty());
        }
        assert_eq!(
            app.handle_key(KeyCode::Enter, KeyModifiers::empty()),
            AppAction::Quit
        );
        for c in "hello".chars() {
            app.handle_key(KeyCode::Char(c), KeyModifiers::empty());
        }
        assert_eq!(
            app.handle_key(KeyCode::Enter, KeyModifiers::empty()),
            AppAction::Send("hello".into())
        );
        assert_eq!(App::interpret_line("/lock"), LineCmd::Lock);
        assert_eq!(App::interpret_line("/copy"), LineCmd::Copy);
        assert_eq!(App::interpret_line(""), LineCmd::Empty);
        // Duress PIN wipes even from the lock screen.
        app.tui.lock();
        for c in "0000".chars() {
            app.handle_key(KeyCode::Char(c), KeyModifiers::empty());
        }
        assert_eq!(
            app.handle_key(KeyCode::Enter, KeyModifiers::empty()),
            AppAction::Wipe
        );
    }

    #[test]
    fn app_renders_all_modes() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = App::new("bob".into(), "tor".into(), false, 60);
        app.push_message("alice", "hi");
        app.set_safety("00000 11111");
        let mut term = Terminal::new(TestBackend::new(60, 20)).unwrap();
        term.draw(|f| app.render(f)).unwrap();
        let buf = term.backend().buffer().clone();
        let text: String = buf
            .content()
            .iter()
            .map(|c| c.symbol().to_string())
            .collect();
        assert!(text.contains("hi"), "messages visible");
        assert!(text.contains("00000"), "safety visible");
        app.tui.lock();
        term.draw(|f| app.render(f)).unwrap();
        let buf = term.backend().buffer().clone();
        let text: String = buf
            .content()
            .iter()
            .map(|c| c.symbol().to_string())
            .collect();
        assert!(text.contains("LOCKED"), "lock screen visible");
    }
}
