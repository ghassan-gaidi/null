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

/// Unpack one received 2048B frame. Handles rekey rotation transparently.
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
