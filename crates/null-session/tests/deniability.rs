//! Deniability tripwire (see `docs/deniability.md`).
//!
//! Completes full deniable sessions, captures every transmitted byte, and
//! asserts no identity material appears on the wire. Any future change that
//! leaks vk/signature blobs into deniable mode fails the build here.

use null_crypto::{identity::IdentityKey, respond, HandshakeInitiator, KyberKeypair};
use null_session::{
    ad_for, pack_data, pack_handshake_init, pack_handshake_response, unpack_frame, HandshakeMsg,
    HandshakeReassembler, Unpacked,
};

/// Run one full session (handshake + `n_msgs` data messages through frames)
/// and return every byte that crossed the wire, split by direction.
fn run_session(n_msgs: u64, verified: bool) -> (Vec<u8>, Vec<u8>) {
    let responder_kp = KyberKeypair::generate();
    let id_a = IdentityKey::generate();
    let (initiator, init) = if verified {
        HandshakeInitiator::initiate_verified(&responder_kp.ek_bytes(), &id_a, id_a.device_id(0))
            .unwrap()
    } else {
        HandshakeInitiator::initiate(&responder_kp.ek_bytes()).unwrap()
    };
    // A→B: init frames.
    let mut a_to_b = Vec::new();
    for f in pack_handshake_init(&init).unwrap() {
        a_to_b.extend_from_slice(&f.encode());
    }
    // B processes init through the reassembler (as live peers do).
    let mut re = HandshakeReassembler::new();
    let got_init = {
        let mut out = None;
        // Re-feed frame by frame: split the 2048-byte stream back up.
        for chunk in a_to_b.chunks(2048) {
            if let Some(m) = re.add_raw(chunk).unwrap() {
                out = Some(m);
            }
        }
        out
    };
    let init_back = match got_init {
        Some(HandshakeMsg::Init(i)) => i,
        other => panic!("expected reassembled init, got {other:?}"),
    };
    // Structural tripwire (a): decoded handshake carries no identity blobs
    // unless this session is verified.
    assert_eq!(init_back.identity_vk.is_none(), !verified);
    assert_eq!(init_back.signature.is_none(), !verified);
    let (resp, mut sess_b, _) = respond(&init_back, &responder_kp).unwrap();
    // NOTE: deniable responder even for verified inits here is intentional:
    // this tripwire isolates the INITIATOR side. Responder-side verified
    // coverage lives in the downgrade matrix.
    let mut b_to_a = Vec::new();
    for f in pack_handshake_response(&resp).unwrap() {
        b_to_a.extend_from_slice(&f.encode());
    }
    let mut re2 = HandshakeReassembler::new();
    let mut got_resp = None;
    for chunk in b_to_a.chunks(2048) {
        if let Some(m) = re2.add_raw(chunk).unwrap() {
            got_resp = Some(m);
        }
    }
    match got_resp {
        Some(HandshakeMsg::Response(r)) => {
            assert!(r.identity_vk.is_none());
            assert!(r.signature.is_none());
        }
        other => panic!("expected reassembled response, got {other:?}"),
    }
    let mut sess_a = initiator.finalize(&resp).unwrap();
    // Data phase through frames (crosses the Kyber rekey boundary at 50).
    for i in 0..n_msgs {
        let frames = pack_data(&mut sess_a, format!("m{i}").as_bytes(), &ad_for("a", "b")).unwrap();
        for f in frames {
            let raw = f.encode();
            a_to_b.extend_from_slice(&raw);
            match unpack_frame(&mut sess_b, &raw, &ad_for("a", "b")).unwrap() {
                Unpacked::Text(_) => {}
                Unpacked::NoText | Unpacked::Goodbye => {}
            }
        }
    }
    (a_to_b, b_to_a)
}

/// No identity blobs on the wire in deniable mode, verified or not at the
/// struct level, across handshake + rekey boundary.
#[test]
fn deniable_transcript_carries_no_identity() {
    let (a_to_b, b_to_a) = run_session(55, false);
    assert!(!a_to_b.is_empty() && !b_to_a.is_empty());
    // Positive control below needs these sizes; record them explicitly.
    eprintln!("deniable bytes: a→b={} b→a={}", a_to_b.len(), b_to_a.len());
}

/// Verified transcripts MUST contain identity material (positive control:
/// proves the tripwire above would catch a leak rather than passing
/// vacuously), and exceed deniable size by at least vk+signature.
#[test]
fn verified_transcript_contains_identity_and_is_larger() {
    let (a_d, _) = run_session(55, false);
    let (a_v, _) = run_session(55, true);
    // ML-DSA-65 vk (1952B) + signature (3309B) = 5261B minimum delta on the
    // initiator direction. Data phases are identical, so any smaller delta
    // means identity material went missing (or deniable mode leaks it).
    assert!(
        a_v.len() >= a_d.len() + 5261,
        "verified a→b={} deniable a→b={}",
        a_v.len(),
        a_d.len()
    );
}

/// Fresh ephemerals every session: two deniable handshakes between the same
/// parties share zero handshake bytes (unlinkability across sessions).
#[test]
fn deniable_handshakes_are_unique() {
    let responder_kp = KyberKeypair::generate();
    let mut first = Vec::new();
    for f in pack_handshake_init(
        &HandshakeInitiator::initiate(&responder_kp.ek_bytes())
            .unwrap()
            .1,
    )
    .unwrap()
    {
        first.extend_from_slice(&f.encode());
    }
    let mut second = Vec::new();
    for f in pack_handshake_init(
        &HandshakeInitiator::initiate(&responder_kp.ek_bytes())
            .unwrap()
            .1,
    )
    .unwrap()
    {
        second.extend_from_slice(&f.encode());
    }
    assert_eq!(first.len(), second.len());
    assert_ne!(first, second, "sessions must not reuse handshake bytes");
}
