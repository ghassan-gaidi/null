//! Lossy / out-of-order REKEY delivery (Task 8).
//!
//! The in-order property (`ratchet_interleave.rs`) cannot reach the
//! `Inbox` recovery paths: `pending` buffering, `MissedRekey` requests,
//! `MAX_REKEY_ROUNDS` exhaustion, `PeerBehind` replays. This file drives
//! those paths deliberately — rekey frames are held back while data keeps
//! flowing (loss), delivered late (reorder), or withheld forever
//! (exhaustion, which must fail loudly, never silently).
//!
//! Frame roles come from the documented `pack_data` contract: a 2-frame
//! result is `[KyberRekey, Data]` (`FrameType` is private to null-frame).

use null_crypto::{respond, HandshakeInitiator, KyberKeypair, Session};
use null_session::{pack_data, Inbox, MAX_REKEY_ROUNDS};
use proptest::prelude::*;

fn two_sessions() -> (Session, Session) {
    let responder_kp = KyberKeypair::generate();
    let (initiator, init) = HandshakeInitiator::initiate(&responder_kp.ek_bytes()).unwrap();
    let (resp, sess_b, _) = respond(&init, &responder_kp).unwrap();
    let sess_a = initiator.finalize(&resp).unwrap();
    (sess_a, sess_b)
}

/// Drive an A→B stream of `n` messages, holding the crossing rekey for
/// `delay` subsequent data frames (0 = in-order control). Returns the
/// texts B produced, in order, plus the peak pending depth observed.
fn run_stream(n: usize, delay: usize, ad: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let (mut a, b) = two_sessions();
    let mut inbox_b = Inbox::new(b);
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut hold_left = 0usize;
    let mut texts: Vec<Vec<u8>> = Vec::new();
    let mut peak_pending = 0usize;

    for i in 0..n {
        let payload = format!("msg-{i:03}").into_bytes();
        let frames = pack_data(&mut a, &payload, ad).unwrap();
        let mut wire: Vec<Vec<u8>> = Vec::new();
        if frames.len() == 2 {
            // Rekey crossing: delay 0 means in-order (rekey first);
            // otherwise hold the rekey and deliver data now.
            if delay == 0 {
                wire.push(frames[0].encode());
            } else {
                held.push(frames[0].encode());
                hold_left = delay;
            }
            wire.push(frames[1].encode());
        } else {
            assert_eq!(frames.len(), 1);
            wire.push(frames[0].encode());
        }
        for raw in wire {
            let out = inbox_b.receive(&raw, ad).unwrap();
            texts.extend(out.texts);
        }
        peak_pending = peak_pending.max(inbox_b.pending_len());
        // Late delivery: after `delay` further messages, release rekeys.
        if hold_left > 0 {
            hold_left -= 1;
            if hold_left == 0 {
                for raw in held.drain(..) {
                    let out = inbox_b.receive(&raw, ad).unwrap();
                    texts.extend(out.texts);
                }
                peak_pending = peak_pending.max(inbox_b.pending_len());
            }
        }
    }
    // End of stream: flush anything still held (loss-then-recover).
    for raw in held.drain(..) {
        let out = inbox_b.receive(&raw, ad).unwrap();
        texts.extend(out.texts);
    }
    (texts, peak_pending)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Held rekeys (loss) and late rekeys (reorder) still deliver every
    /// message exactly once, in order. Delays stay within the recovery
    /// budget (`MAX_REKEY_ROUNDS`); beyond it is the exhaustion test's job.
    #[test]
    fn rekey_loss_and_reorder_recovers_losslessly(
        n in 55..66usize,
        delay in 0..(MAX_REKEY_ROUNDS as usize + 1),
    ) {
        let ad = null_session::ad_for("alice", "bob");
        let (texts, peak) = run_stream(n, delay, &ad);
        let expected: Vec<Vec<u8>> = (0..n).map(|i| format!("msg-{i:03}").into_bytes()).collect();
        prop_assert!(texts == expected, "lossless + ordered under delay {}", delay);
        if delay > 0 {
            prop_assert!(peak > 0, "delay {} must buffer (non-vacuous)", delay);
        }
    }
}

/// Withholding the rekey past the retry budget must fail loudly with the
/// re-handshake directive — never stall, never silently drop.
#[test]
fn rekey_withheld_forever_fails_loudly() {
    let (mut a, b) = two_sessions();
    let ad = null_session::ad_for("alice", "bob");
    let mut inbox_b = Inbox::new(b);
    let mut pre_texts = 0usize;
    let mut loud_err = false;
    // Enough sends to cross the rekey boundary, then keep going with the
    // rekey permanently held.
    for i in 0..70usize {
        let payload = format!("msg-{i:03}").into_bytes();
        let frames = pack_data(&mut a, &payload, &ad).unwrap();
        let datas: Vec<Vec<u8>> = if frames.len() == 2 {
            vec![frames[1].encode()] // rekey dropped on the floor
        } else {
            vec![frames[0].encode()]
        };
        let mut failed = false;
        for raw in datas {
            match inbox_b.receive(&raw, &ad) {
                Ok(out) => pre_texts += out.texts.len(),
                Err(e) => {
                    assert!(
                        format!("{e:?}").contains("re-handshake"),
                        "must name the recovery path: {e:?}"
                    );
                    failed = true;
                    loud_err = true;
                    break;
                }
            }
        }
        if failed {
            break;
        }
    }
    assert!(pre_texts > 0, "pre-boundary messages must have arrived");
    assert!(loud_err, "withheld rekey must eventually fail loudly");
}
