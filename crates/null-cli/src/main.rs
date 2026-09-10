//! `null` binary: bootstrap → discovery → communicate → wipe (§12).

mod secure_input;

use anyhow::Result;
use clap::Parser;
use null_core::ConnectionString;
use null_transport::{Endpoint, Multiplexer};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "null",
    version,
    about = "Null v2.0 — PQ terminal messenger (RAM-only)"
)]
struct Args {
    /// Open benign decoy IRC-like interface; real session behind /unlock.
    #[arg(long)]
    safe: bool,
    /// Enable ML-DSA identity + safety-number verification.
    #[arg(long)]
    verified: bool,
    /// Pure deniable mode (default): strip all signature material.
    #[arg(long, default_value_t = true)]
    deniable: bool,
    /// Read keystrokes from /dev/input to bypass terminal keyloggers (needs root).
    #[arg(long)]
    secure_input: bool,
    /// Peer's null:// connection string, or `loopback` for the self-test demo.
    #[arg(long)]
    peer: Option<String>,
    /// Transports in priority order, e.g. tor,i2p,nym.
    #[arg(long, default_value = "tor,i2p,nym")]
    transports: String,
    /// Auto-lock seconds (default 30 min idle per §8.4 dead-man baseline).
    #[arg(long, default_value_t = 30 * 60)]
    auto_lock_secs: u64,
    /// Dead man's switch: panic-wipe keys and exit after N idle seconds
    /// (§8.4). 0 disables (default); distinct from auto-lock above.
    #[arg(long, default_value_t = 0)]
    dead_man_secs: u64,
    /// Panic-wipe when a new /dev node appears (unknown USB insertion, §8.4).
    #[arg(long)]
    usbguard: bool,
    /// Tor control port for ephemeral onion provisioning (0 = disabled).
    #[arg(long, default_value_t = 0)]
    control_port: u16,
    /// Responder mode: bind 127.0.0.1:<PORT> (fronted by your onion service)
    /// and serve one inbound handshake. Prints your null:// string.
    #[arg(long)]
    listen: Option<u16>,
    /// Full-screen Ratatui chat (loopback or live sessions; real pipeline).
    #[arg(long)]
    tui: bool,
    /// Local-secret backend: `software` (Tier 1, RAM-only default) or
    /// `check` (also probe for TPM/YubiKey isolates).
    #[arg(long, default_value = "software")]
    hsm: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    install_signal_wipe();

    if args.secure_input && !is_root() {
        eprintln!("[null] WARN: --secure-input needs root; falling back to /dev/tty");
    }

    // Bootstrap: transports.
    let transports: Vec<null_core::TransportKind> = args
        .transports
        .split(',')
        .map(|s| {
            s.parse()
                .map_err(|e: null_core::NullError| anyhow::anyhow!("{e}"))
        })
        .collect::<Result<_>>()?;
    let mux = Multiplexer::new(transports);
    let elected = mux.elect().await;
    eprintln!("[null] transports ready; elected path: {elected}");

    if args.usbguard {
        spawn_usbguard();
    }

    // HSM tier (§7.5): Tier 1 software default; never mixed into the shared
    // ratchet root (peers could not converge) — guards local secrets only.
    {
        use null_memory::{HardwareHsmProbe, HsmBackend, SoftwareHsm};
        let _soft = SoftwareHsm::new();
        eprintln!("[null] HSM: {} (isolates_keys=false)", _soft.name());
        if args.hsm == "check" {
            eprintln!("[null] HSM probe: {}", HardwareHsmProbe::report());
        } else if args.hsm != "software" {
            eprintln!("[null] WARN: unknown --hsm backend, using software");
        }
    }

    if let Some(port) = args.listen {
        run_listener(
            port,
            args.control_port,
            &args.transports,
            args.verified,
            args.auto_lock_secs,
            args.secure_input,
            args.dead_man_secs,
            args.tui,
        )
        .await?;
        secure_exit();
    }

    if args.control_port != 0 {
        match mux.provision_onion(args.control_port, 80).await {
            Ok(host) => eprintln!("[null] ephemeral onion: null://{host} (share out-of-band)"),
            Err(e) => eprintln!("[null] onion provisioning failed: {e}"),
        }
    }

    // Discovery: peer connection string.
    if let Some(peer) = args.peer.as_deref() {
        if peer == "loopback" {
            if args.tui {
                tui_loopback(
                    args.safe,
                    args.verified,
                    args.auto_lock_secs,
                    args.dead_man_secs,
                )
                .await?;
            } else {
                demo_loopback(
                    args.safe,
                    args.verified,
                    args.auto_lock_secs,
                    args.dead_man_secs,
                )
                .await?;
            }
            secure_exit();
        }
        let cs = ConnectionString::parse(peer).map_err(|e| anyhow::anyhow!("bad --peer: {e}"))?;
        eprintln!(
            "[null] peer onion: {}….onion",
            &cs.onion_host[..8.min(cs.onion_host.len())]
        );
        let live = std::env::var("NULL_LIVE_TRANSPORT").as_deref() == Ok("1");
        let mut mux = Multiplexer::new(cs.transports.clone());
        // Direct-TCP escape hatch for local listener tests: a `null://`
        // string with host `listener` dials NULL_DIRECT_ADDR instead of a
        // SOCKS proxy (never used for real .onion peers).
        let direct = cs.onion_host == "listener";
        if live || direct {
            let conn = if direct {
                let addr = std::env::var("NULL_DIRECT_ADDR")
                    .unwrap_or_else(|_| "127.0.0.1:18080".to_string());
                let stream = tokio::net::TcpStream::connect(&addr).await?;
                null_transport::TransportConn::new_live(
                    null_core::TransportKind::Tor,
                    Endpoint {
                        onion_host: cs.onion_host.clone(),
                        port: 80,
                    },
                    stream,
                )
            } else {
                match mux.dial_live(&cs.onion_host, 80).await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[null] live dial failed (all transports): {e}");
                        secure_exit();
                    }
                }
            };
            eprintln!("[null] circuit established");
            match live_handshake(
                conn,
                &cs,
                args.verified,
                args.auto_lock_secs,
                args.secure_input,
                args.dead_man_secs,
                args.tui,
            )
            .await
            {
                Ok(()) => secure_exit(),
                Err(e) => {
                    eprintln!("[null] session failed: {e:#}");
                    secure_exit();
                }
            }
        } else {
            let ep = Endpoint {
                onion_host: cs.onion_host.clone(),
                port: 80,
            };
            match mux.dial(&ep).await {
                Ok(c) => eprintln!(
                    "[null] circuit via {} (stub — set NULL_LIVE_TRANSPORT=1 for live dial)",
                    c.kind
                ),
                Err(e) => eprintln!("[null] dial failed (all transports): {e}"),
            }
        }
        if args.verified {
            if let Some(fp) = cs.identity_fingerprint {
                eprintln!("[null] verified mode: peer fingerprint {fp}");
            } else {
                eprintln!("[null] verified mode requested but peer string has no i= fingerprint");
            }
        } else if args.deniable {
            eprintln!("[null] deniable mode: no signatures (default)");
        }
    } else {
        eprintln!("[null] paste peer's null:// string to begin handshake (or pass --peer).");
    }

    if args.safe {
        eprintln!("[null] decoy mode: benign IRC-like UI. /unlock <pin> reveals session.");
    }

    eprintln!(
        "[null] TUI hints: {} | auto-lock {}s | clipboard clears in 5s",
        null_tui::layout_hint(args.safe),
        args.auto_lock_secs
    );
    eprintln!("[null] memory: {}", null_memory::sleep_protection_status());
    eprintln!("[null] hint: --peer loopback runs a self-contained E2E demo.");
    eprintln!("[null] idle — press Ctrl-C to panic-wipe (<100ms) and exit 0.");

    // Park until signal. Real chat loop (ratchet + shaper + frames) runs here
    // in the next milestone; the secure lifecycle (wipe on exit) is already live.
    tokio::signal::ctrl_c().await?;
    secure_exit()
}

/// Drive loopback traffic until both directions are quiescent (bounded):
/// deliver queued raws into inboxes, route outbound replies back.
/// Returns collected `(a_texts, b_texts)`. Exercises the same recovery
/// path (rekey requests/replays) as live peers.
async fn exchange_loopback(
    a_end: &mut null_transport::LoopbackHandle,
    b_end: &mut null_transport::LoopbackHandle,
    ia: &mut null_session::Inbox,
    ib: &mut null_session::Inbox,
    ad_ab: &[u8],
    ad_ba: &[u8],
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let mut a_texts = Vec::new();
    let mut b_texts = Vec::new();
    for _ in 0..8 {
        let mut moved = false;
        while let Ok(raw) = b_end.try_recv_raw() {
            moved = true;
            let out = ib.receive(&raw, ad_ab)?;
            if let Some(n) = out.notice {
                eprintln!("[null] resync: {n}");
            }
            b_texts.extend(out.texts);
            for f in &out.outbound {
                a_end.send_raw(f.encode()).unwrap();
            }
        }
        while let Ok(raw) = a_end.try_recv_raw() {
            moved = true;
            let out = ia.receive(&raw, ad_ba)?;
            if let Some(n) = out.notice {
                eprintln!("[null] resync: {n}");
            }
            a_texts.extend(out.texts);
            for f in &out.outbound {
                b_end.send_raw(f.encode()).unwrap();
            }
        }
        if !moved {
            break;
        }
    }
    Ok((a_texts, b_texts))
}

/// Self-contained E2E demo over an in-memory loopback circuit: real
/// handshake → ratchet → 2048B frames → shaper → transport → decrypt,
/// then an interactive self-chat REPL. No daemons required.
///
/// All traffic flows through [`null_session::Inbox`] on both ends, so rekey
/// replays and requests exercise the same recovery path as live peers.
async fn demo_loopback(
    decoy: bool,
    verified: bool,
    auto_lock_secs: u64,
    dead_man_secs: u64,
) -> Result<()> {
    use null_crypto::{
        identity::IdentityKey, respond, respond_verified, HandshakeInitiator, KyberKeypair,
    };
    use null_frame::TrafficShaper;
    use null_session::{ad_for, pack_data, Inbox};
    use null_transport::loopback_pair;
    use tokio::io::{AsyncBufReadExt, BufReader};

    eprintln!("[null] loopback demo: handshake → frames → shaper → decrypt");
    if decoy {
        eprintln!("[null] decoy mode: benign IRC-like UI. /unlock <pin> reveals session.");
    }

    // Handshake: B advertises a long-term Kyber ek (as in its null:// string).
    // --verified upgrades to mutual ML-DSA-65 authentication + pinning.
    let kp_b = KyberKeypair::generate();
    let id_a = verified.then(IdentityKey::generate);
    let id_b = verified.then(IdentityKey::generate);
    let (init, init_msg) = match &id_a {
        Some(id) => HandshakeInitiator::initiate_verified(&kp_b.ek_bytes(), id)?,
        None => HandshakeInitiator::initiate(&kp_b.ek_bytes())?,
    };
    let (resp, sess_b, _) = match &id_b {
        Some(id) => respond_verified(&init_msg, &kp_b, id, None)?,
        None => respond(&init_msg, &kp_b)?,
    };
    let sess_a = if verified {
        let fp_b = id_b.as_ref().unwrap().fingerprint();
        init.finalize_verified(&resp, Some(&fp_b))?
    } else {
        init.finalize(&resp)?
    };
    let mut ia = Inbox::new(sess_a);
    let mut ib = Inbox::new(sess_b);
    eprintln!("[null] handshake complete (3DH deniable + ML-KEM-1024)");

    if verified {
        let sn = null_identity::safety_number(
            &id_a.as_ref().unwrap().verifying_bytes(),
            &id_b.as_ref().unwrap().verifying_bytes(),
            b"loopback-demo",
        );
        eprintln!("[null] safety number: {sn}");
        if let Ok(qr) = null_identity::safety_number_qr_ascii(&sn) {
            eprintln!("[null] in-person scan code:\n{qr}");
        }
    }

    let ad_ab = ad_for("alice.loopback", "bob.loopback");
    let ad_ba = ad_for("bob.loopback", "alice.loopback");
    let (mut a_end, mut b_end) = loopback_pair();
    let mut shaper = TrafficShaper::new();

    // One scripted ping-pong through the full wire path first.
    for f in pack_data(ia.session_mut(), b"ping", &ad_ab)? {
        if shaper.try_consume() {
            a_end.send_raw(f.encode()).unwrap();
        } else {
            tokio::time::sleep(TrafficShaper::next_delay()).await;
            a_end.send_raw(f.encode()).unwrap();
        }
    }
    let (_, b_texts) =
        exchange_loopback(&mut a_end, &mut b_end, &mut ia, &mut ib, &ad_ab, &ad_ba).await?;
    for pt in &b_texts {
        eprintln!("[bob] {}", String::from_utf8_lossy(pt));
    }
    for f in pack_data(ib.session_mut(), b"pong", &ad_ba)? {
        b_end.send_raw(f.encode()).unwrap();
    }
    let (a_texts, _) =
        exchange_loopback(&mut a_end, &mut b_end, &mut ia, &mut ib, &ad_ab, &ad_ba).await?;
    for pt in &a_texts {
        eprintln!("[alice] {}", String::from_utf8_lossy(pt));
    }

    eprintln!("[null] type lines to send (self-chat echoes decrypt); /quit exits.");
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    let mut locked = false;
    let mut last_activity = std::time::Instant::now();
    let mut last_peer_text = String::new();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => secure_exit(),
            _ = tick.tick() => {
                if dead_man_secs > 0 && last_activity.elapsed().as_secs() >= dead_man_secs {
                    eprintln!("[null] dead man's switch: {dead_man_secs}s idle — wiping");
                    secure_exit();
                }
                // Idle lock (§8.4).
                if !locked && last_activity.elapsed().as_secs() >= auto_lock_secs {
                    locked = true;
                    eprintln!("[null] auto-locked after {auto_lock_secs}s idle — /unlock to resume");
                }
            }
            line = lines.next_line() => {
                let Some(line) = line? else {
                    // Stdin EOF (piped input exhausted): wipe and exit.
                    secure_exit();
                };
                last_activity = std::time::Instant::now();
                let cmd = line.trim();
                if cmd == "/quit" {
                    secure_exit();
                }
                if cmd == "/lock" {
                    locked = true;
                    eprintln!("[null] locked — type /unlock to resume");
                    continue;
                }
                if cmd == "/unlock" {
                    locked = false;
                    last_activity = std::time::Instant::now();
                    eprintln!("[null] unlocked");
                    continue;
                }
                if locked {
                    eprintln!("[null] locked — type /unlock to resume");
                    continue;
                }
                if cmd.is_empty() {
                    continue;
                }
                if cmd == "/copy" {
                    if last_peer_text.is_empty() {
                        eprintln!("[null] nothing to copy yet");
                    } else {
                        null_tui::clipboard_copy_and_schedule_clear(&last_peer_text);
                        eprintln!("[null] copied; clipboard clears in 5s");
                    }
                    continue;
                }
                // Shaped send: burst then jittered delay (§6.2).
                for f in pack_data(ia.session_mut(), cmd.as_bytes(), &ad_ab)? {
                    if !shaper.try_consume() {
                        tokio::time::sleep(TrafficShaper::next_delay()).await;
                    }
                    a_end.send_raw(f.encode()).unwrap();
                }
                // Loopback echo: what B decrypts on the wire (with recovery).
                let (_, b_texts) =
                    exchange_loopback(&mut a_end, &mut b_end, &mut ia, &mut ib, &ad_ab, &ad_ba)
                        .await?;
                for pt in &b_texts {
                    last_peer_text = String::from_utf8_lossy(pt).into_owned();
                    eprintln!("[bob] {last_peer_text}");
                }
            }
        }
    }
}

/// Full-screen Ratatui chat over a loopback triple-ratchet session.
/// Same pipeline as live peers (handshake → frames → shaper → decrypt);
/// the "network" is an in-memory circuit. Demo PIN is 1234, duress 0000.
async fn tui_loopback(
    decoy: bool,
    verified: bool,
    auto_lock_secs: u64,
    dead_man_secs: u64,
) -> Result<()> {
    use crossterm::{
        event::{self, Event},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use null_crypto::{respond, HandshakeInitiator, KyberKeypair};
    use null_frame::TrafficShaper;
    use null_session::{ad_for, pack_data, Inbox};
    use null_transport::loopback_pair;
    use null_tui::{App, AppAction};
    use ratatui::{backend::CrosstermBackend, Terminal};

    let kp_b = KyberKeypair::generate();
    let (init, init_msg) = HandshakeInitiator::initiate(&kp_b.ek_bytes())?;
    let (resp, sess_b, _) = respond(&init_msg, &kp_b)?;
    let sess_a = init.finalize(&resp)?;
    let mut ia = Inbox::new(sess_a);
    let mut ib = Inbox::new(sess_b);
    let ad_ab = ad_for("alice.loopback", "bob.loopback");
    let ad_ba = ad_for("bob.loopback", "alice.loopback");
    let (mut a_end, mut b_end) = loopback_pair();
    let mut shaper = TrafficShaper::new();

    let mut app = App::new(
        "bob (loopback)".into(),
        "loopback".into(),
        decoy,
        auto_lock_secs,
    );
    if verified {
        app.set_safety(null_identity::safety_number(
            &ia.session_mut().kyber_ek_bytes(),
            &ib.session_mut().kyber_ek_bytes(),
            b"loopback-demo",
        ));
    }
    // Scripted hello through the wire path (with recovery).
    for f in pack_data(ia.session_mut(), b"ping", &ad_ab)? {
        a_end.send_raw(f.encode()).unwrap();
    }
    let (_, b_texts) =
        exchange_loopback(&mut a_end, &mut b_end, &mut ia, &mut ib, &ad_ab, &ad_ba).await?;
    for pt in &b_texts {
        app.push_message("bob", &String::from_utf8_lossy(pt));
    }
    app.push_message("sys", "session up — Enter sends, /quit exits");

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout))?;
    let restore = |term: &mut Terminal<CrosstermBackend<std::io::Stdout>>| {
        let _ = disable_raw_mode();
        let _ = execute!(term.backend_mut(), LeaveAlternateScreen);
    };

    loop {
        app.poll_auto_lock();
        if dead_man_secs > 0 && app.tui.last_activity.elapsed().as_secs() >= dead_man_secs {
            restore(&mut term);
            eprintln!("[null] dead man's switch: {dead_man_secs}s idle — wiping");
            secure_exit();
        }
        term.draw(|f| app.render(f))?;
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match app.handle_key(key.code, key.modifiers) {
                    AppAction::None => {}
                    AppAction::Quit => break,
                    AppAction::Wipe => {
                        restore(&mut term);
                        secure_exit();
                    }
                    AppAction::Copy(text) => {
                        null_tui::clipboard_copy_and_schedule_clear(&text);
                        app.set_notice("copied; clears in 5s");
                    }
                    AppAction::Send(cmd) => {
                        for f in pack_data(ia.session_mut(), cmd.as_bytes(), &ad_ab)? {
                            if !shaper.try_consume() {
                                tokio::time::sleep(TrafficShaper::next_delay()).await;
                            }
                            a_end.send_raw(f.encode()).unwrap();
                        }
                        let (_, b_texts) = exchange_loopback(
                            &mut a_end, &mut b_end, &mut ia, &mut ib, &ad_ab, &ad_ba,
                        )
                        .await?;
                        for pt in &b_texts {
                            app.push_message("you", &cmd);
                            app.push_message("bob", &String::from_utf8_lossy(pt));
                        }
                    }
                }
            }
        }
    }
    restore(&mut term);
    Ok(())
}
/// Initiator handshake + live chat over an established circuit.
/// Sends our init (Control frame), awaits the response blob, finalizes the
/// triple-ratchet session, then runs the shaped send/receive loop.
async fn live_handshake(
    mut conn: null_transport::TransportConn,
    cs: &ConnectionString,
    verified: bool,
    auto_lock_secs: u64,
    secure: bool,
    dead_man_secs: u64,
    tui: bool,
) -> Result<()> {
    use base64::Engine;
    use null_crypto::HandshakeInitiator;
    use null_session::{ad_for_bytes, pack_handshake_init, HandshakeMsg, HandshakeReassembler};

    let ek_bytes = base64::engine::general_purpose::STANDARD
        .decode(cs.kyber_pubkey_b64.trim())
        .map_err(|e| anyhow::anyhow!("peer's k= is not valid base64 ML-KEM-1024 ek: {e}"))?;
    // Verified mode mints an ephemeral ML-DSA-65 identity for this session.
    let own_id = verified.then(null_crypto::identity::IdentityKey::generate);
    let (init, init_msg) = match &own_id {
        Some(id) => HandshakeInitiator::initiate_verified(&ek_bytes, id)?,
        None => HandshakeInitiator::initiate(&ek_bytes)?,
    };
    for frame in pack_handshake_init(&init_msg)? {
        conn.send_blob(&frame.encode()).await?;
    }
    eprintln!("[null] handshake init sent; awaiting peer response…");
    let mut re = HandshakeReassembler::new();
    let resp = loop {
        let raw = conn.recv_blob().await?;
        // Data frames here would be a peer bug (no session yet) — reject.
        match re.add_raw(&raw)? {
            Some(HandshakeMsg::Response(r)) => break r,
            Some(HandshakeMsg::Init(_)) => {
                anyhow::bail!("peer replied with init (responder-only mode unsupported)")
            }
            None => continue,
        }
    };
    let session = match &own_id {
        Some(_) => init.finalize_verified(&resp, cs.identity_fingerprint.as_deref())?,
        None => init.finalize(&resp)?,
    };
    eprintln!("[null] session established (triple ratchet active)");

    if verified {
        let peer_id_material: &[u8] = resp.identity_vk.as_deref().unwrap_or(ek_bytes.as_slice());
        let sn = null_identity::safety_number(
            &own_id.as_ref().unwrap().verifying_bytes(),
            peer_id_material,
            cs.onion_host.as_bytes(),
        );
        eprintln!("[null] safety number: {sn}");
        eprintln!(
            "[null] confirm out-of-band{}",
            match &cs.identity_fingerprint {
                Some(fp) => format!(" (pinned peer fingerprint: {fp})"),
                None => " (TOFU: no i= fingerprint in peer string!)".to_string(),
            }
        );
        if let Ok(qr) = null_identity::safety_number_qr_ascii(&sn) {
            eprintln!("[null] in-person scan code:\n{qr}");
        }
    }

    let ad_out = ad_for_bytes(&session.kyber_ek_bytes(), &ek_bytes);
    let ad_in = ad_for_bytes(&ek_bytes, &session.kyber_ek_bytes());
    if tui {
        if secure {
            eprintln!("[null] WARN: --tui owns the keyboard; ignoring --secure-input");
        }
        let mut app = null_tui::App::new(
            cs.onion_host.clone(),
            conn.kind.to_string(),
            false,
            auto_lock_secs,
        );
        if verified {
            let peer_vk = resp.identity_vk.as_deref().unwrap_or(ek_bytes.as_slice());
            app.set_safety(null_identity::safety_number(
                &own_id.as_ref().unwrap().verifying_bytes(),
                peer_vk,
                cs.onion_host.as_bytes(),
            ));
        }
        chat_loop_tui(session, conn, &ad_out, &ad_in, dead_man_secs, app).await
    } else {
        chat_loop(
            session,
            conn,
            &ad_out,
            &ad_in,
            auto_lock_secs,
            secure,
            dead_man_secs,
        )
        .await
    }
}

/// Responder mode (§12 discovery, inbound side): bind loopback, optionally
/// provision our onion, serve one handshake, then chat. Prints the
/// `null://` string the initiator needs. Eight scalar knobs would trip the
/// arg-count lint, so they stay grouped by role in the signature below.
#[allow(clippy::too_many_arguments)]
async fn run_listener(
    port: u16,
    control_port: u16,
    transports: &str,
    verified: bool,
    auto_lock_secs: u64,
    secure: bool,
    dead_man_secs: u64,
    tui: bool,
) -> Result<()> {
    use base64::Engine;
    use null_crypto::{respond, respond_verified, KyberKeypair};
    use null_session::{ad_for_bytes, pack_handshake_response, HandshakeMsg, HandshakeReassembler};

    let own_kp = KyberKeypair::generate();
    let ek_b64 = base64::engine::general_purpose::STANDARD.encode(own_kp.ek_bytes());
    // Verified mode mints an ephemeral ML-DSA-65 identity whose fingerprint
    // the initiator pins via the `i=` parameter.
    let own_id = verified.then(null_crypto::identity::IdentityKey::generate);

    let onion_host = if control_port != 0 {
        let mux = Multiplexer::new(vec![null_core::TransportKind::Tor]);
        let host = mux.provision_onion(control_port, 80).await?;
        // Strip the `.onion` suffix for the connection-string struct.
        host.strip_suffix(".onion").unwrap_or(&host).to_string()
    } else {
        // No Tor control: share the ek with a placeholder host; the peer
        // dials us directly (local test) or via their own rendezvous config.
        "listener".to_string()
    };
    let ours = ConnectionString {
        onion_host: onion_host.clone(),
        kyber_pubkey_b64: ek_b64,
        identity_fingerprint: own_id.as_ref().map(|id| id.fingerprint()),
        transports: transports
            .split(',')
            .map(|s| {
                s.parse()
                    .map_err(|e: null_core::NullError| anyhow::anyhow!("{e}"))
            })
            .collect::<Result<_>>()?,
    };
    eprintln!("[null] your connect string:\n{}", ours.to_uri());

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    eprintln!("[null] listening on 127.0.0.1:{port} (front this with your onion service)…");
    let (stream, from) = tokio::select! {
        _ = tokio::signal::ctrl_c() => secure_exit(),
        accepted = listener.accept() => accepted?,
    };
    eprintln!("[null] inbound from {from}; performing handshake…");
    let mut conn = null_transport::TransportConn::new_live(
        null_core::TransportKind::Tor,
        null_transport::Endpoint {
            onion_host: "inbound".into(),
            port,
        },
        stream,
    );
    let mut re = HandshakeReassembler::new();
    let init = loop {
        let raw = conn.recv_blob().await?;
        match re.add_raw(&raw)? {
            Some(HandshakeMsg::Init(i)) => break i,
            Some(HandshakeMsg::Response(_)) => {
                anyhow::bail!("unexpected response on listener (two initiators?)")
            }
            None => continue,
        }
    };
    let (resp, session, _) = match &own_id {
        Some(id) => respond_verified(&init, &own_kp, id, None)?,
        None => respond(&init, &own_kp)?,
    };
    for frame in pack_handshake_response(&resp)? {
        conn.send_blob(&frame.encode()).await?;
    }
    eprintln!("[null] session established (triple ratchet active)");
    if verified {
        // Same vk pair as the initiator attests (canonical sort inside
        // safety_number makes order irrelevant, so both displays agree).
        let own_vk = own_id.as_ref().unwrap().verifying_bytes();
        let peer_vk = init
            .identity_vk
            .clone()
            .unwrap_or_else(|| init.kyber_ek.clone());
        let sn = null_identity::safety_number(&own_vk, &peer_vk, onion_host.as_bytes());
        eprintln!("[null] safety number: {sn} — confirm out-of-band");
        if let Ok(qr) = null_identity::safety_number_qr_ascii(&sn) {
            eprintln!("[null] in-person scan code:\n{qr}");
        }
    }
    let ad_out = ad_for_bytes(&own_kp.ek_bytes(), &init.kyber_ek);
    let ad_in = ad_for_bytes(&init.kyber_ek, &own_kp.ek_bytes());
    if tui {
        let mut app = null_tui::App::new(
            "inbound".into(),
            conn.kind.to_string(),
            false,
            auto_lock_secs,
        );
        if verified {
            let own_vk = own_id.as_ref().unwrap().verifying_bytes();
            let peer_vk = init
                .identity_vk
                .clone()
                .unwrap_or_else(|| init.kyber_ek.clone());
            app.set_safety(null_identity::safety_number(
                &own_vk,
                &peer_vk,
                onion_host.as_bytes(),
            ));
        }
        chat_loop_tui(session, conn, &ad_out, &ad_in, dead_man_secs, app).await
    } else {
        chat_loop(
            session,
            conn,
            &ad_out,
            &ad_in,
            auto_lock_secs,
            secure,
            dead_man_secs,
        )
        .await
    }
}

/// Shaped send/receive loop shared by initiator and responder sessions.
///
/// Line input arrives over one channel fed by stdin and — when `secure` and
/// available (root + evdev) — by the grabbed-keyboard reader (§8.3).
/// Reception runs through [`null_session::Inbox`] so lost PQ rekeys heal
/// automatically instead of wedging the session.
async fn chat_loop(
    session: null_crypto::Session,
    mut conn: null_transport::TransportConn,
    ad_out: &[u8],
    ad_in: &[u8],
    auto_lock_secs: u64,
    secure: bool,
    dead_man_secs: u64,
) -> Result<()> {
    use null_frame::TrafficShaper;
    use null_session::{pack_data, Inbox};

    let mut inbox = Inbox::new(session);

    let mut shaper = TrafficShaper::new();
    let mut locked = false;
    let mut last_activity = std::time::Instant::now();
    let mut last_peer_text = String::new();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Option<String>>();
    std::thread::spawn({
        let tx = tx.clone();
        move || {
            for line in std::io::BufRead::lines(std::io::stdin().lock()) {
                if tx.send(line.ok()).is_err() {
                    break;
                }
            }
            let _ = tx.send(None);
        }
    });
    if secure {
        if secure_input::available() {
            eprintln!("[null] secure-input: evdev keyboard grabbed (bypasses terminal keyloggers)");
            std::thread::spawn(move || loop {
                match secure_input::read_line_grabbed() {
                    Ok(line) => {
                        if tx.send(Some(line)).is_err() {
                            break;
                        }
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_secs(1)),
                }
            });
        } else {
            eprintln!("[null] WARN: --secure-input needs root + evdev; stdin active");
        }
    }
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    eprintln!("[null] type lines to send; /quit exits, /lock locks, /copy copies last message.");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => secure_exit(),
            _ = tick.tick() => {
                if dead_man_secs > 0 && last_activity.elapsed().as_secs() >= dead_man_secs {
                    eprintln!("[null] dead man's switch: {dead_man_secs}s idle — wiping");
                    secure_exit();
                }
                if !locked && last_activity.elapsed().as_secs() >= auto_lock_secs {
                    locked = true;
                    eprintln!("[null] auto-locked after {auto_lock_secs}s idle — /unlock to resume");
                }
                // Idle cover traffic: indistinguishable dummy frame (§6.3).
                if shaper.try_consume() {
                    let dummy =
                        null_frame::Frame::dummy(inbox.session_mut().send_counter());
                    let _ = conn.send_blob(&dummy.encode()).await;
                }
            }
            inbound = conn.recv_blob() => {
                let raw = match inbound {
                    Ok(raw) => raw,
                    Err(_) => {
                        // FIN/RST: data sent before it is still delivered by
                        // the kernel first (recv_blob drains the buffer), so
                        // reaching here means the peer is truly gone.
                        eprintln!("[null] peer disconnected — wiping");
                        drain_inbound(&mut conn, &mut inbox, ad_in).await;
                        secure_exit();
                    }
                };
                let out = inbox.receive(&raw, ad_in)?;
                if let Some(n) = out.notice {
                    eprintln!("[null] resync: {n}");
                }
                for f in &out.outbound {
                    conn.send_blob(&f.encode()).await?;
                }
                for pt in &out.texts {
                    last_activity = std::time::Instant::now();
                    last_peer_text = String::from_utf8_lossy(pt).into_owned();
                    eprintln!("[peer] {last_peer_text}");
                }
                if out.goodbye {
                    eprintln!("[peer] left — wiping");
                    drain_inbound(&mut conn, &mut inbox, ad_in).await;
                    secure_exit();
                }
            }
            line = async { rx.recv().await } => {
                let Some(line) = line.flatten() else {
                    graceful_quit(&mut conn, &mut inbox, ad_in).await;
                    secure_exit()
                };
                last_activity = std::time::Instant::now();
                let cmd = line.trim();
                if cmd == "/quit" {
                    graceful_quit(&mut conn, &mut inbox, ad_in).await;
                    secure_exit();
                }
                if cmd == "/lock" {
                    locked = true;
                    eprintln!("[null] locked — type /unlock to resume");
                    continue;
                }
                if cmd == "/unlock" {
                    locked = false;
                    last_activity = std::time::Instant::now();
                    eprintln!("[null] unlocked");
                    continue;
                }
                if locked {
                    eprintln!("[null] locked — type /unlock to resume");
                    continue;
                }
                if cmd.is_empty() { continue; }
                if cmd == "/copy" {
                    if last_peer_text.is_empty() {
                        eprintln!("[null] nothing to copy yet");
                    } else {
                        null_tui::clipboard_copy_and_schedule_clear(&last_peer_text);
                        eprintln!("[null] copied; clipboard clears in 5s");
                    }
                    continue;
                }
                for f in pack_data(inbox.session_mut(), cmd.as_bytes(), ad_out)? {
                    if !shaper.try_consume() {
                        tokio::time::sleep(TrafficShaper::next_delay()).await;
                    }
                    conn.send_blob(&f.encode()).await?;
                }
            }
        }
    }
}

/// Orderly quit: announce goodbye, then drain inbound briefly so the peer's
/// in-flight messages still print. Draining our receive buffer ALSO prevents
/// our close from RST-ing the connection (which would discard the peer's
/// queued bytes) — the goodbye's counterpart.
async fn graceful_quit(
    conn: &mut null_transport::TransportConn,
    inbox: &mut null_session::Inbox,
    ad_in: &[u8],
) {
    use null_session::pack_goodbye;
    if let Ok(frame) = pack_goodbye(inbox.session_mut().send_counter()) {
        let _ = conn.send_blob(&frame.encode()).await;
    }
    drain_inbound(conn, inbox, ad_in).await;
}

/// Read inbound for up to ~2s, printing texts (peer goodbye included).
async fn drain_inbound(
    conn: &mut null_transport::TransportConn,
    inbox: &mut null_session::Inbox,
    ad_in: &[u8],
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, conn.recv_blob()).await {
            Ok(Ok(raw)) => match inbox.receive(&raw, ad_in) {
                Ok(out) => {
                    for pt in &out.texts {
                        eprintln!("[peer] {}", String::from_utf8_lossy(pt));
                    }
                }
                Err(_) => break,
            },
            _ => break,
        }
    }
}

/// Full-screen Ratatui variant of [`chat_loop`] for live sessions.
/// Same pipeline (shaped sends, [`Inbox`] recovery, goodbye/drain); input
/// comes from crossterm key events routed through [`null_tui::App`].
async fn chat_loop_tui(
    session: null_crypto::Session,
    mut conn: null_transport::TransportConn,
    ad_out: &[u8],
    ad_in: &[u8],
    dead_man_secs: u64,
    mut app: null_tui::App,
) -> Result<()> {
    use crossterm::{
        event::{self, Event},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use null_frame::TrafficShaper;
    use null_session::{pack_data, Inbox};
    use null_tui::AppAction;
    use ratatui::{backend::CrosstermBackend, Terminal};

    let mut inbox = Inbox::new(session);
    let mut shaper = TrafficShaper::new();
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout))?;
    let restore = |term: &mut Terminal<CrosstermBackend<std::io::Stdout>>| {
        let _ = disable_raw_mode();
        let _ = execute!(term.backend_mut(), LeaveAlternateScreen);
    };
    app.push_message("sys", "session up — Enter sends, Esc quits");
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));
    loop {
        app.poll_auto_lock();
        if dead_man_secs > 0 && app.tui.last_activity.elapsed().as_secs() >= dead_man_secs {
            restore(&mut term);
            eprintln!("[null] dead man's switch: {dead_man_secs}s idle — wiping");
            secure_exit();
        }
        term.draw(|f| app.render(f))?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                restore(&mut term);
                secure_exit();
            }
            _ = tick.tick() => {
                if shaper.try_consume() {
                    let dummy =
                        null_frame::Frame::dummy(inbox.session_mut().send_counter());
                    let _ = conn.send_blob(&dummy.encode()).await;
                }
                while event::poll(std::time::Duration::from_millis(0))? {
                    let Event::Key(key) = event::read()? else { continue };
                    match app.handle_key(key.code, key.modifiers) {
                        AppAction::None => {}
                        AppAction::Quit => {
                            restore(&mut term);
                            return Ok(());
                        }
                        AppAction::Wipe => {
                            restore(&mut term);
                            secure_exit();
                        }
                        AppAction::Copy(text) => {
                            null_tui::clipboard_copy_and_schedule_clear(&text);
                            app.set_notice("copied; clears in 5s");
                        }
                        AppAction::Send(text) => {
                            for f in pack_data(inbox.session_mut(), text.as_bytes(), ad_out)? {
                                if !shaper.try_consume() {
                                    tokio::time::sleep(TrafficShaper::next_delay()).await;
                                }
                                conn.send_blob(&f.encode()).await?;
                            }
                        }
                    }
                }
            }
            inbound = conn.recv_blob() => {
                let raw = match inbound {
                    Ok(raw) => raw,
                    Err(_) => {
                        restore(&mut term);
                        eprintln!("[null] peer disconnected — wiping");
                        drain_inbound(&mut conn, &mut inbox, ad_in).await;
                        secure_exit();
                    }
                };
                let out = inbox.receive(&raw, ad_in)?;
                if let Some(n) = out.notice {
                    app.set_notice(format!("resync: {n}"));
                }
                for f in &out.outbound {
                    conn.send_blob(&f.encode()).await?;
                }
                for pt in &out.texts {
                    app.push_message("peer", &String::from_utf8_lossy(pt));
                }
                if out.goodbye {
                    restore(&mut term);
                    eprintln!("[peer] left — wiping");
                    drain_inbound(&mut conn, &mut inbox, ad_in).await;
                    secure_exit();
                }
            }
        }
    }
}

/// USBGuard (§8.4): panic-wipe if a new /dev node appears (best-effort poll).
fn spawn_usbguard() {
    std::thread::spawn(|| {
        let snapshot = || {
            std::fs::read_dir("/dev")
                .map(|rd| {
                    rd.filter_map(|e| e.ok().map(|d| d.file_name()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        let mut known = snapshot();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let now = snapshot();
            if now.len() > known.len() && now.iter().any(|n| !known.contains(n)) {
                eprintln!("[null] USBGuard: new device node — panic wipe");
                null_memory::panic_wipe_all_and_clear_screen();
                std::process::exit(0);
            }
            known = now;
        }
    });
}

fn install_signal_wipe() {
    // Rust-level guard: on panic, clear screen before unwinding out.
    std::panic::set_hook(Box::new(|info| {
        eprintln!("[null] panic — wiping keys");
        null_memory::panic_wipe_all_and_clear_screen();
        eprintln!("panic: {info}");
    }));
    #[cfg(unix)]
    unsafe {
        // Best-effort: ignore errors; tokio ctrl_c covers SIGINT path.
        let _ = signal_hook::low_level::register(signal_hook::consts::SIGTERM, || {
            null_memory::panic_wipe_all_and_clear_screen();
            std::process::exit(0);
        });
        let _ = signal_hook::low_level::register(signal_hook::consts::SIGHUP, || {
            null_memory::panic_wipe_all_and_clear_screen();
            std::process::exit(0);
        });
    }
}

fn secure_exit() -> ! {
    null_memory::panic_wipe_all_and_clear_screen();
    std::process::exit(0);
}

#[allow(dead_code)]
fn hold_systemd_delay_lock() -> Option<std::process::Child> {
    // Hold a systemd-logind delay lock so sleep triggers wipe first:
    // `systemd-inhibit --what=sleep --mode=delay --who=null --why=wipe sleep infinity`
    std::process::Command::new("systemd-inhibit")
        .args([
            "--what=sleep",
            "--mode=delay",
            "--who=null",
            "--why=panic-wipe-before-ram-to-disk",
            "sleep",
            "infinity",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()
}

pub(crate) fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::getuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[allow(dead_code)]
fn _keep_duration_used(_d: Duration) {}
