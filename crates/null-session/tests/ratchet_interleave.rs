//! Stateful interleaved-ratchet fuzz (Track D).
//!
//! Random alternating A↔B message flows run through the *whole* stack —
//! handshake, 2048-byte frame layer, per-message ECDH ratchet, and the
//! periodic Kyber rekey every 50 sends — asserting lossless, ordered,
//! exact-match delivery in both directions on every single frame.
//!
//! proptest keeps this deterministic on failure (seed is printed), so a
//! regression becomes a one-line repro, and shrinking minimizes the flow.
//! Stable Rust only (no nightly/miri/cargo-fuzz): plain cargo test.

use null_crypto::{respond, HandshakeInitiator, KyberKeypair, Session};
use null_session::{
    ad_for, pack_data, pack_handshake_init, pack_handshake_response, unpack_frame, HandshakeMsg,
    HandshakeReassembler, Unpacked,
};
use proptest::prelude::*;

/// One directional send of an opaque payload.
#[derive(Debug, Clone)]
enum Act {
    A2B(Vec<u8>),
    B2A(Vec<u8>),
}

/// Payloads stretch the AEAD/frame path (header+tag ≈ 64B over the 1984B
/// frame cap; 1280B stays comfortably inside while exercising multi-byte
/// plaintexts and cross-boundary sizes).
fn any_act() -> impl Strategy<Value = Act> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 1..1280_usize).prop_map(Act::A2B),
        prop::collection::vec(any::<u8>(), 1..1280_usize).prop_map(Act::B2A),
    ]
}

/// Run the full handshake through frames (as live peers do) and return the
/// two converged sessions.
fn two_sessions() -> (Session, Session) {
    let responder_kp = KyberKeypair::generate();
    let (initiator, init) = HandshakeInitiator::initiate(&responder_kp.ek_bytes()).unwrap();

    // A→B init through the 2048B reassembler.
    let mut re = HandshakeReassembler::new();
    let mut got = None;
    for f in pack_handshake_init(&init).unwrap() {
        if let Some(m) = re.add_raw(&f.encode()).unwrap() {
            got = Some(m);
        }
    }
    let init_back = match got {
        Some(HandshakeMsg::Init(i)) => i,
        other => panic!("expected reassembled init, got {other:?}"),
    };
    let (resp, sess_b, _) = respond(&init_back, &responder_kp).unwrap();

    // B→A response through the reassembler, fused back into session A.
    let mut re2 = HandshakeReassembler::new();
    let mut got_resp = None;
    for f in pack_handshake_response(&resp).unwrap() {
        if let Some(m) = re2.add_raw(&f.encode()).unwrap() {
            got_resp = Some(m);
        }
    }
    let resp_back = match got_resp {
        Some(HandshakeMsg::Response(r)) => r,
        other => panic!("expected reassembled response, got {other:?}"),
    };
    let sess_a = initiator.finalize(&resp_back).unwrap();
    (sess_a, sess_b)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Deliver every generated action in order, exactly once, both ways —
    /// across the Kyber rekey boundary every 50 sends. Any dropped,
    /// duplicated, reordered, or corrupted plaintext fails the property.
    #[test]
    fn interleaved_ratchet_is_lossless_and_ordered(
        acts in prop::collection::vec(any_act(), 1..72_usize)
    ) {
        let (mut a, mut b) = two_sessions();
        let ad = ad_for("alice", "bob");
        let mut sent_a: Vec<Vec<u8>> = Vec::new();
        let mut sent_b: Vec<Vec<u8>> = Vec::new();
        let mut rcvd_a: Vec<Vec<u8>> = Vec::new();
        let mut rcvd_b: Vec<Vec<u8>> = Vec::new();
        let mut rekey_a = 0u32;
        let mut rekey_b = 0u32;

        for act in acts {
            match act {
                Act::A2B(payload) => {
                    // pack_data emits [KyberRekey, Data] exactly when the
                    // session needs one (§4.2) — a 2-frame result is the
                    // rekey crossing; FrameType is private to null-frame, so
                    // count via this documented contract.
                    let frames = pack_data(&mut a, &payload, &ad).unwrap();
                    if frames.len() == 2 {
                        rekey_a += 1;
                    }
                    for f in frames {
                        match unpack_frame(&mut b, &f.encode(), &ad).unwrap() {
                            Unpacked::Text(pt) => {
                                assert_eq!(pt, payload, "A2B plaintext mismatch");
                                rcvd_b.push(pt);
                            }
                            Unpacked::NoText | Unpacked::Goodbye => {}
                        }
                    }
                    sent_a.push(payload);
                }
                Act::B2A(payload) => {
                    let frames = pack_data(&mut b, &payload, &ad).unwrap();
                    if frames.len() == 2 {
                        rekey_b += 1;
                    }
                    for f in frames {
                        match unpack_frame(&mut a, &f.encode(), &ad).unwrap() {
                            Unpacked::Text(pt) => {
                                assert_eq!(pt, payload, "B2A plaintext mismatch");
                                rcvd_a.push(pt);
                            }
                            Unpacked::NoText | Unpacked::Goodbye => {}
                        }
                    }
                    sent_b.push(payload);
                }
            }
        }

        // Lossless + order-preserving both directions.
        assert_eq!(rcvd_b.len(), sent_a.len(), "dropped A2B messages");
        assert_eq!(rcvd_a.len(), sent_b.len(), "dropped B2A messages");
        assert_eq!(rcvd_a, sent_b, "B2A stream altered");
        assert_eq!(rcvd_b, sent_a, "A2B stream altered");

        // Ratchet counters track exactly the number of user messages.
        assert_eq!(a.send_counter(), sent_a.len() as u64);
        assert_eq!(b.send_counter(), sent_b.len() as u64);

        // Long runs MUST have crossed the periodic Kyber rekey boundary
        // (every 50 sends) in whichever direction got there — a flow that
        // pretends to work but never re-encapsulates fails loudly here.
        if sent_a.len() >= 51 {
            assert!(rekey_a >= 1, "A→B crossed 50 sends without a rekey");
        }
        if sent_b.len() >= 51 {
            assert!(rekey_b >= 1, "B→A crossed 50 sends without a rekey");
        }
    }
}
