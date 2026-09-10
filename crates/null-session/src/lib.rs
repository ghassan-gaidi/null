//! End-to-end session pipeline: ratchet message ↔ 2048B frame.
//!
//! Pure packing/unpacking over [`null_crypto::Session`] + [`null_frame::Frame`]
//! shared by the CLI, the loopback demo, and the TCP integration test.
//! Async transport I/O stays with the caller; this module never touches
//! the net and leaves zero forensic residue beyond its stack buffers.

use null_core::{FrameType, PROTOCOL_VERSION};
use null_crypto::{EncryptedMessage, HandshakeInit, HandshakeResponse, Session};
use null_frame::Frame;

/// Associated data bound into every AEAD message (§4.2):
/// `sender_onion ‖ receiver_onion ‖ protocol_version`.
pub fn ad_for(sender_onion: &str, receiver_onion: &str) -> Vec<u8> {
    format!("{sender_onion}|{receiver_onion}|{PROTOCOL_VERSION}").into_bytes()
}

/// Direction-bound AD from long-term Kyber eks (both peers know both eks
/// after the handshake, so sender's `ad_out` always equals receiver's
/// `ad_in` — unlike onion labels, which differ per side's viewpoint).
pub fn ad_for_bytes(sender_ek: &[u8], receiver_ek: &[u8]) -> Vec<u8> {
    let mut s = String::with_capacity(sender_ek.len() * 2 + receiver_ek.len() * 2 + 8);
    for b in sender_ek {
        s.push_str(&format!("{b:02x}"));
    }
    s.push('|');
    for b in receiver_ek {
        s.push_str(&format!("{b:02x}"));
    }
    s.push_str(&format!("|{PROTOCOL_VERSION}"));
    s.into_bytes()
}

/// Inner tags for handshake blobs carried in `Control` frames.
pub const HS_INIT_TAG: u8 = 0x01;
pub const HS_RESPONSE_TAG: u8 = 0x02;
/// Orderly shutdown notice (`Control` frame, empty payload).
pub const GOODBYE_TAG: u8 = 0x10;
/// Rekey replay request (`Control` frame, payload `from_gen` u64 BE):
/// "re-send your rekey events newer than this generation".
pub const REKEY_REQUEST_TAG: u8 = 0x11;
/// Max buffered undecryptable messages awaiting a missed rekey.
pub const MAX_PENDING: usize = 16;
/// Consecutive unanswered rekey requests before declaring the session
/// unrecoverable without a fresh handshake.
pub const MAX_REKEY_ROUNDS: u32 = 3;
/// Max handshake-blob bytes per frame; Kyber-1024 material (1568B ek + 1568B
/// ct) cannot fit one 2048B frame, so inits fragment across two (§4.1).
pub const HS_FRAG_MAX: usize = 1900;

/// Pack a handshake init into 1+ `Control` frames.
/// Layout per frame: `tag(1) ‖ frag_idx(1) ‖ frag_total(1) ‖ chunk`.
pub fn pack_handshake_init(init: &HandshakeInit) -> anyhow::Result<Vec<Frame>> {
    pack_handshake_blob(HS_INIT_TAG, &init.encode())
}

pub fn pack_handshake_response(resp: &HandshakeResponse) -> anyhow::Result<Vec<Frame>> {
    pack_handshake_blob(HS_RESPONSE_TAG, &resp.encode())
}

fn pack_handshake_blob(tag: u8, blob: &[u8]) -> anyhow::Result<Vec<Frame>> {
    if blob.is_empty() {
        return Err(anyhow::anyhow!("empty handshake blob"));
    }
    let chunks: Vec<&[u8]> = blob.chunks(HS_FRAG_MAX).collect();
    if chunks.len() > 255 {
        return Err(anyhow::anyhow!("handshake blob too large"));
    }
    chunks
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut payload = vec![tag, i as u8, chunks.len() as u8];
            payload.extend_from_slice(c);
            Frame::new(FrameType::Control, 0, payload)
                .map_err(|e| anyhow::anyhow!("handshake frame: {e}"))
        })
        .collect()
}

/// Reassembles fragmented handshake frames into whole messages.
/// One handshake per direction at a time (matches the §4.1 flow).
#[derive(Default)]
pub struct HandshakeReassembler {
    tag: Option<u8>,
    total: Option<u8>,
    parts: Vec<Option<Vec<u8>>>,
}

impl HandshakeReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one raw 2048B frame. Returns the message once all fragments
    /// arrived; `Ok(None)` while still waiting.
    pub fn add_raw(&mut self, raw: &[u8]) -> anyhow::Result<Option<HandshakeMsg>> {
        let frame = Frame::decode(raw).map_err(|e| anyhow::anyhow!("frame decode: {e}"))?;
        if frame.frame_type != FrameType::Control || frame.payload.len() < 3 {
            return Err(anyhow::anyhow!("not a handshake frame"));
        }
        let (tag, idx, total) = (frame.payload[0], frame.payload[1], frame.payload[2]);
        if tag != HS_INIT_TAG && tag != HS_RESPONSE_TAG {
            return Err(anyhow::anyhow!("unknown handshake tag {tag:#x}"));
        }
        if total == 0 || idx >= total {
            return Err(anyhow::anyhow!("bad handshake frag {idx}/{total}"));
        }
        match (self.tag, self.total) {
            (Some(t), Some(n)) if t != tag || n != total => {
                return Err(anyhow::anyhow!("handshake interleave not supported"));
            }
            _ => {}
        }
        self.tag = Some(tag);
        self.total = Some(total);
        if self.parts.is_empty() {
            self.parts.resize(total as usize, None);
        }
        self.parts[idx as usize] = Some(frame.payload[3..].to_vec());
        if self.parts.iter().any(|p| p.is_none()) {
            return Ok(None);
        }
        let blob: Vec<u8> = self
            .parts
            .iter()
            .flatten()
            .flat_map(|p| p.iter())
            .copied()
            .collect();
        self.parts.clear();
        self.tag = None;
        self.total = None;
        match tag {
            HS_INIT_TAG => Ok(Some(HandshakeMsg::Init(
                HandshakeInit::decode(&blob).map_err(|e| anyhow::anyhow!("init decode: {e}"))?,
            ))),
            _ => Ok(Some(HandshakeMsg::Response(
                HandshakeResponse::decode(&blob)
                    .map_err(|e| anyhow::anyhow!("response decode: {e}"))?,
            ))),
        }
    }
}

#[derive(Debug)]
pub enum HandshakeMsg {
    Init(HandshakeInit),
    Response(HandshakeResponse),
}

/// Unpack a single-frame `Control` handshake message (responses, or any
/// blob that fit one frame). Multi-frame inits need [`HandshakeReassembler`].
#[allow(dead_code)]
pub fn unpack_handshake(raw: &[u8]) -> anyhow::Result<HandshakeMsg> {
    let mut re = HandshakeReassembler::new();
    match re.add_raw(raw)? {
        Some(m) => Ok(m),
        None => Err(anyhow::anyhow!("handshake fragmented; use reassembler")),
    }
}

#[derive(Debug)]
pub enum Unpacked {
    /// Decrypted chat plaintext.
    Text(Vec<u8>),
    /// Orderly peer shutdown (reply with goodbye, then exit).
    Goodbye,
    /// Kyber rekey / dummy / other control frame: no user text.
    NoText,
}

/// Pack one user message into 1–2 frames.
///
/// If `session.needs_kyber_rekey()`, a `KyberRekey` frame carrying the fresh
/// encapsulation `ct` (to the peer's long-term ek stored at handshake) is
/// emitted FIRST (receiver must process frames in order), followed by the
/// `Data` frame.
pub fn pack_data(session: &mut Session, plaintext: &[u8], ad: &[u8]) -> anyhow::Result<Vec<Frame>> {
    let mut frames = Vec::with_capacity(2);
    if session.needs_kyber_rekey() {
        let ct = session
            .kyber_rekey_initiate()
            .map_err(|e| anyhow::anyhow!("kyber rekey: {e}"))?;
        frames.push(
            Frame::new(FrameType::KyberRekey, session.send_counter(), ct)
                .map_err(|e| anyhow::anyhow!("rekey frame: {e}"))?,
        );
    }
    let msg = session
        .encrypt(plaintext, ad)
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
    let wire = msg.encode();
    // Counter on the frame mirrors the ratchet counter for ordering.
    frames.push(
        Frame::new(FrameType::Data, msg.counter, wire)
            .map_err(|e| anyhow::anyhow!("data frame: {e}"))?,
    );
    Ok(frames)
}

/// Pack an orderly-shutdown notice (send before draining on quit).
pub fn pack_goodbye(counter: u64) -> anyhow::Result<Frame> {
    Frame::new(FrameType::Control, counter, vec![GOODBYE_TAG])
        .map_err(|e| anyhow::anyhow!("goodbye frame: {e}"))
}

/// Pack a rekey replay request for generation `from_gen`.
pub fn pack_rekey_request(counter: u64, from_gen: u64) -> anyhow::Result<Frame> {
    let mut payload = vec![REKEY_REQUEST_TAG];
    payload.extend_from_slice(&from_gen.to_be_bytes());
    Frame::new(FrameType::Control, counter, payload)
        .map_err(|e| anyhow::anyhow!("rekey request frame: {e}"))
}

/// Unpack one received 2048B frame. Handles rekey rotation transparently.
///
/// Generation mismatches surface as [`null_core::NullError::MissedRekey`]
/// / `PeerBehind` (via `anyhow`) WITHOUT mutating session state — use
/// [`Inbox`] for automatic buffering, requests, and retries.
pub fn unpack_frame(session: &mut Session, raw: &[u8], ad: &[u8]) -> anyhow::Result<Unpacked> {
    let frame = Frame::decode(raw).map_err(|e| anyhow::anyhow!("frame decode: {e}"))?;
    if frame.frame_type == FrameType::Control && frame.payload.first() == Some(&GOODBYE_TAG) {
        return Ok(Unpacked::Goodbye);
    }
    match frame.frame_type {
        FrameType::Data => {
            let msg = EncryptedMessage::decode(&frame.payload)
                .map_err(|e| anyhow::anyhow!("message decode: {e}"))?;
            let pt = session
                .decrypt(&msg, ad)
                .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
            Ok(Unpacked::Text(pt))
        }
        FrameType::KyberRekey => {
            session
                .kyber_rekey_receive(&frame.payload)
                .map_err(|e| anyhow::anyhow!("rekey receive: {e}"))?;
            Ok(Unpacked::NoText)
        }
        FrameType::Dummy | FrameType::Control => Ok(Unpacked::NoText),
    }
}

/// Stateful receive endpoint with lossless rekey recovery.
///
/// Data frames that arrive ahead of their PQ rekey are buffered (bounded)
/// while a `REKEY_REQUEST` goes out; each applied rekey retries the buffer.
/// Data from a stale peer epoch is dropped with a notice while our retained
/// rekeys are pushed to heal them. After [`MAX_REKEY_ROUNDS`] unanswered
/// rounds the session is declared unrecoverable (fresh handshake needed).
pub struct Inbox {
    session: Session,
    pending: std::collections::VecDeque<(EncryptedMessage, Vec<u8>)>,
    request_rounds: u32,
}

impl Inbox {
    pub fn new(session: Session) -> Self {
        Self {
            session,
            pending: std::collections::VecDeque::new(),
            request_rounds: 0,
        }
    }

    pub fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Feed one raw 2048B frame. `outbound` frames must be transmitted in
    /// order (rekey replays / requests); `texts` holds all newly readable
    /// plaintexts; `notice` carries operator-visible drop/heal events.
    pub fn receive(&mut self, raw: &[u8], ad: &[u8]) -> anyhow::Result<InboxOut> {
        let frame = Frame::decode(raw).map_err(|e| anyhow::anyhow!("frame decode: {e}"))?;
        let mut out = InboxOut::default();
        match frame.frame_type {
            FrameType::Dummy => {}
            FrameType::Control => {
                if frame.payload.first() == Some(&GOODBYE_TAG) {
                    out.goodbye = true;
                } else if frame.payload.first() == Some(&REKEY_REQUEST_TAG) {
                    if frame.payload.len() != 9 {
                        return Err(anyhow::anyhow!("malformed rekey request"));
                    }
                    let from = u64::from_be_bytes(frame.payload[1..9].try_into().unwrap());
                    for (_, ct) in self.session.rekey_events_since(from) {
                        out.outbound.push(
                            Frame::new(FrameType::KyberRekey, self.session.send_counter(), ct)
                                .map_err(|e| anyhow::anyhow!("rekey replay: {e}"))?,
                        );
                    }
                }
            }
            FrameType::KyberRekey => {
                self.session
                    .kyber_rekey_receive(&frame.payload)
                    .map_err(|e| anyhow::anyhow!("rekey receive: {e}"))?;
                self.request_rounds = 0;
                self.retry_pending(&mut out);
            }
            FrameType::Data => {
                let msg = EncryptedMessage::decode(&frame.payload)
                    .map_err(|e| anyhow::anyhow!("message decode: {e}"))?;
                match self.session.decrypt(&msg, ad) {
                    Ok(pt) => {
                        self.request_rounds = 0;
                        out.texts.push(pt);
                    }
                    Err(null_core::NullError::MissedRekey { have, .. }) => {
                        if self.pending.len() >= MAX_PENDING {
                            self.pending.pop_front();
                            out.notice = Some("dropped oldest buffered message (overflow)".into());
                        }
                        self.pending.push_back((msg, ad.to_vec()));
                        self.request_rounds += 1;
                        if self.request_rounds > MAX_REKEY_ROUNDS {
                            return Err(anyhow::anyhow!(
                                "PQ resync impossible after {MAX_REKEY_ROUNDS} rounds: re-handshake required"
                            ));
                        }
                        out.outbound.push(
                            pack_rekey_request(self.session.send_counter(), have)
                                .map_err(|e| anyhow::anyhow!("request pack: {e}"))?,
                        );
                        out.notice = Some(format!(
                            "missed PQ rekey (have gen {have}): buffered, requested replay"
                        ));
                    }
                    Err(null_core::NullError::PeerBehind { have, want }) => {
                        // Peer is behind: push our retained rekeys so their
                        // FUTURE messages decrypt. This stale message itself
                        // used an abandoned root and cannot be recovered.
                        for (_, ct) in self.session.rekey_events_since(want) {
                            out.outbound.push(
                                Frame::new(FrameType::KyberRekey, self.session.send_counter(), ct)
                                    .map_err(|e| anyhow::anyhow!("rekey push: {e}"))?,
                            );
                        }
                        out.notice = Some(format!(
                            "dropped message from stale PQ epoch (peer gen {want}, ours {have})"
                        ));
                    }
                    Err(e) => return Err(anyhow::anyhow!("decrypt: {e}")),
                }
            }
        }
        Ok(out)
    }

    /// Try buffered messages again (each carries the AD it arrived with).
    fn retry_pending(&mut self, out: &mut InboxOut) {
        let mut still_pending = std::collections::VecDeque::new();
        while let Some((msg, ad)) = self.pending.pop_front() {
            match self.session.decrypt(&msg, &ad) {
                Ok(pt) => out.texts.push(pt),
                Err(_) => still_pending.push_back((msg, ad)),
            }
        }
        self.pending = still_pending;
        if self.pending.is_empty() {
            self.request_rounds = 0;
        }
    }
}

#[derive(Debug, Default)]
pub struct InboxOut {
    pub texts: Vec<Vec<u8>>,
    pub outbound: Vec<Frame>,
    pub goodbye: bool,
    pub notice: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use null_crypto::{respond, HandshakeInitiator, KyberKeypair};

    fn handshake_pair() -> (Session, Session) {
        let kp_b = KyberKeypair::generate();
        let ek_b = kp_b.ek_bytes();
        let (init, init_msg) = HandshakeInitiator::initiate(&ek_b).unwrap();
        let (resp, sess_b, _) = respond(&init_msg, &kp_b).unwrap();
        let sess_a = init.finalize(&resp).unwrap();
        (sess_a, sess_b)
    }

    fn inbox_pair() -> (Inbox, Inbox) {
        let (a, b) = handshake_pair();
        (Inbox::new(a), Inbox::new(b))
    }

    #[test]
    fn inbox_recovers_lost_rekey_losslessly() {
        let (mut ia, mut ib) = inbox_pair();
        let ad = ad_for("alice", "bob");
        // A advances two PQ generations WITHOUT transmitting the rekey
        // frames (simulating loss), then sends one Data frame.
        ia.session_mut().kyber_rekey_initiate().unwrap(); // gen 0→1
        ia.session_mut().kyber_rekey_initiate().unwrap(); // gen 1→2
        let frames = pack_data(ia.session_mut(), b"lost rekey msg", &ad).unwrap();
        assert_eq!(frames.len(), 1, "Data only; rekey frames were lost");
        // B is at gen 0. Deliver Data(gen2) only.
        let data_raw = frames[0].encode();
        let out = ib.receive(&data_raw, &ad).unwrap();
        assert!(out.texts.is_empty(), "nothing decryptable yet");
        assert_eq!(ib.pending_len(), 1, "message buffered");
        assert_eq!(out.outbound.len(), 1, "rekey request emitted");
        assert!(out.notice.unwrap().contains("missed PQ rekey"));
        // A answers the request with retained replays (gen 1 AND 2).
        let req_raw = out.outbound[0].encode();
        let ans = ia.receive(&req_raw, &ad).unwrap();
        assert!(ans.texts.is_empty());
        assert_eq!(ans.outbound.len(), 2, "both missed rekeys replayed");
        // B applies replays in order; the buffered message decrypts.
        let mut healed_texts = Vec::new();
        for f in &ans.outbound {
            let r = ib.receive(&f.encode(), &ad).unwrap();
            healed_texts.extend(r.texts);
        }
        assert_eq!(healed_texts.len(), 1);
        assert_eq!(healed_texts[0], b"lost rekey msg");
        assert_eq!(ib.pending_len(), 0);
        assert_eq!(
            ia.session_mut().kyber_generation(),
            ib.session_mut().kyber_generation()
        );
    }

    #[test]
    fn inbox_pushes_rekeys_to_stale_peer() {
        let (mut ia, mut ib) = inbox_pair();
        let ad = ad_for("alice", "bob");
        // A advances two generations alone (rekeys never transmitted).
        ia.session_mut().kyber_rekey_initiate().unwrap();
        ia.session_mut().kyber_rekey_initiate().unwrap();
        // B (gen 0) sends data; A (gen 2) sees a stale epoch: drops the
        // message but pushes both retained rekeys so B heals forward.
        let frames = pack_data(ib.session_mut(), b"stale hello", &ad).unwrap();
        let out = ia.receive(&frames[0].encode(), &ad).unwrap();
        assert!(out.texts.is_empty());
        assert_eq!(out.outbound.len(), 2, "both generations pushed");
        assert!(out.notice.unwrap().contains("stale PQ epoch"));
        // B applies the pushes and converges.
        for f in &out.outbound {
            let r = ib.receive(&f.encode(), &ad).unwrap();
            assert!(r.texts.is_empty());
        }
        assert_eq!(
            ia.session_mut().kyber_generation(),
            ib.session_mut().kyber_generation()
        );
        // Conversation resumes on the healed root.
        let frames = pack_data(ib.session_mut(), b"healed hi", &ad).unwrap();
        let out = ia.receive(&frames[0].encode(), &ad).unwrap();
        assert_eq!(out.texts.len(), 1);
        assert_eq!(out.texts[0], b"healed hi");
    }

    #[test]
    fn inbox_gives_up_after_max_rounds() {
        let (mut ia, mut ib) = inbox_pair();
        let ad = ad_for("alice", "bob");
        ia.session_mut().kyber_rekey_initiate().unwrap();
        let frames = pack_data(ia.session_mut(), b"x", &ad).unwrap();
        let raw = frames[0].encode();
        // Answer requests with silence (drop outbound): rounds accumulate.
        for _ in 0..=MAX_REKEY_ROUNDS {
            if let Err(e) = ib.receive(&raw, &ad) {
                assert!(format!("{e:?}").contains("re-handshake"));
                return;
            }
        }
        panic!("should have declared the session unrecoverable");
    }

    /// Drive one packed message from `a` to `b` through full 2048B frames.
    /// Returns the number of frames emitted (2 when a PQ rekey fired).
    fn pump(a: &mut Session, b: &mut Session, ad: &[u8], text: &[u8]) -> usize {
        let frames = pack_data(a, text, ad).unwrap();
        let n = frames.len();
        for f in &frames {
            assert_eq!(f.encode().len(), 2048);
            let raw = f.encode();
            match unpack_frame(b, &raw, ad).unwrap() {
                Unpacked::Text(pt) => assert_eq!(pt, text),
                Unpacked::NoText | Unpacked::Goodbye => assert_ne!(f.frame_type, FrameType::Data),
            }
        }
        n
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let (mut a, mut b) = handshake_pair();
        let ad = ad_for("alice", "bob");
        let frames = pack_data(&mut a, b"hello pipeline", &ad).unwrap();
        assert_eq!(frames.len(), 1);
        for f in &frames {
            assert_eq!(f.encode().len(), 2048);
        }
        let raw = frames[0].encode();
        match unpack_frame(&mut b, &raw, &ad).unwrap() {
            Unpacked::Text(pt) => assert_eq!(pt, b"hello pipeline"),
            Unpacked::NoText | Unpacked::Goodbye => panic!("expected text"),
        }
    }

    #[test]
    fn handshake_frame_roundtrip() {
        let kp_b = KyberKeypair::generate();
        let (init, init_msg) = HandshakeInitiator::initiate(&kp_b.ek_bytes()).unwrap();
        // Init fragments (Kyber material > 1 frame); reassembler restores it.
        let frames = pack_handshake_init(&init_msg).unwrap();
        assert!(frames.len() >= 2);
        let mut re = HandshakeReassembler::new();
        let mut got = None;
        for f in &frames {
            assert_eq!(f.encode().len(), 2048);
            got = re.add_raw(&f.encode()).unwrap();
        }
        match got.unwrap() {
            HandshakeMsg::Init(back) => assert_eq!(back.ephemeral_pub, init_msg.ephemeral_pub),
            _ => panic!("expected init"),
        }
        let (resp, _, _) = respond(&init_msg, &kp_b).unwrap();
        // Responses fragment too once verified (vk + sig exceed a frame).
        let rframes = pack_handshake_response(&resp).unwrap();
        let mut re2 = HandshakeReassembler::new();
        let mut rgot = None;
        for f in &rframes {
            rgot = re2.add_raw(&f.encode()).unwrap();
        }
        match rgot.unwrap() {
            HandshakeMsg::Response(back) => assert_eq!(back.ephemeral_pub, resp.ephemeral_pub),
            _ => panic!("expected response"),
        }
        let _ = init;
    }

    #[test]
    fn rekey_fires_at_50_and_heals_over_frames() {
        let (mut a, mut b) = handshake_pair();
        let ad = ad_for("alice", "bob");
        // 50 messages: no rekey frames yet (trigger is >= 50).
        for i in 0..50 {
            let n = pump(&mut a, &mut b, &ad, format!("msg{i}").as_bytes());
            assert_eq!(n, 1, "message {i} should not rekey");
        }
        // 51st message carries KyberRekey + Data; B heals and reads text.
        let n = pump(&mut a, &mut b, &ad, b"post-quantum");
        assert_eq!(n, 2);
        // Conversation continues on the healed root in both directions.
        let frames = pack_data(&mut b, b"reply on healed root", &ad).unwrap();
        for f in frames {
            match unpack_frame(&mut a, &f.encode(), &ad).unwrap() {
                Unpacked::Text(pt) => assert_eq!(pt, b"reply on healed root"),
                Unpacked::NoText | Unpacked::Goodbye => panic!("expected reply text"),
            }
        }
    }
}
