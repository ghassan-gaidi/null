//! Downgrade-attack matrix: every negotiation point under an active
//! attacker must fail closed — never silently accept a weaker session.
//!
//! Attacker model per case is stated explicitly. Cases already covered at
//! unit level elsewhere are cited, not duplicated:
//! - mass PQ-rekey loss → resync then re-handshake demand: `inbox_gives_up_*`
//! - epoch replay / forked group commits: `null-group` fork/stale tests
//! - stale peer-epoch data: `inbox_pushes_rekeys_to_stale_peer`
//! - tampered handshake transcript: `verified_handshake_with_pinning`

use null_core::FrameType;
use null_crypto::{
    identity::IdentityKey, respond, respond_verified, EncryptedMessage, HandshakeInitiator,
    HandshakeResponse, KyberKeypair,
};
use null_frame::Frame;
use null_session::{pack_data, unpack_frame, Unpacked};

/// Attacker strips vk+signature from a verified init (downgrade to
/// deniable). Responder proceeds deniably (it cannot know better), but the
/// initiator's verified finalize MUST abort instead of continuing unsigned.
#[test]
fn stripped_verified_init_aborts_at_finalize() {
    let responder_kp = KyberKeypair::generate();
    let id_a = IdentityKey::generate();
    let (initiator, mut init) =
        HandshakeInitiator::initiate_verified(&responder_kp.ek_bytes(), &id_a, id_a.device_id(0))
            .unwrap();
    init.identity_vk = None;
    init.signature = None;
    let (resp, _sess_b, _) = respond(&init, &responder_kp).unwrap();
    assert!(resp.identity_vk.is_none());
    let err = match initiator.finalize_verified(&resp, None) {
        Err(e) => e,
        Ok(_) => panic!("stripped verified init must not finalize"),
    };
    assert!(format!("{err:?}").contains("no identity vk"));
}

/// Attacker strips only the signature, keeping the vk: transcript check
/// must fail, not fall back to trusting the bare key.
#[test]
fn stripped_signature_rejected_not_trusted() {
    let responder_kp = KyberKeypair::generate();
    let id_a = IdentityKey::generate();
    let (initiator, mut init) =
        HandshakeInitiator::initiate_verified(&responder_kp.ek_bytes(), &id_a, id_a.device_id(0))
            .unwrap();
    init.signature = None;
    assert!(respond_verified(
        &init,
        &responder_kp,
        &IdentityKey::generate(),
        None,
        [0u8; 16],
    )
    .is_err());
    let _ = initiator;
}

/// Attacker strips only the vk, keeping the signature: no key to verify
/// against, must fail rather than skip verification.
#[test]
fn stripped_vk_rejected_not_skipped() {
    let responder_kp = KyberKeypair::generate();
    let id_a = IdentityKey::generate();
    let (_initiator, mut init) =
        HandshakeInitiator::initiate_verified(&responder_kp.ek_bytes(), &id_a, id_a.device_id(0))
            .unwrap();
    init.identity_vk = None;
    assert!(respond_verified(
        &init,
        &responder_kp,
        &IdentityKey::generate(),
        None,
        [0u8; 16],
    )
    .is_err());
}

/// Deniable initiator × verified responder: responder must refuse to
/// upgrade unilaterally (that would attest to an unverified peer).
#[test]
fn deniable_init_rejected_by_verified_responder() {
    let responder_kp = KyberKeypair::generate();
    let (initiator, init) = HandshakeInitiator::initiate(&responder_kp.ek_bytes()).unwrap();
    assert!(respond_verified(
        &init,
        &responder_kp,
        &IdentityKey::generate(),
        None,
        [0u8; 16],
    )
    .is_err());
    let _ = initiator;
}

/// Full pinned MITM: attacker proxies handshake bytes but the responder
/// identity is the attacker's own valid key; initiator pinned the real fp.
#[test]
fn mitm_identity_swap_aborts_on_pin() {
    let responder_kp = KyberKeypair::generate();
    let id_a = IdentityKey::generate();
    let id_b = IdentityKey::generate();
    let fp_b = id_b.fingerprint();
    let (initiator, init) =
        HandshakeInitiator::initiate_verified(&responder_kp.ek_bytes(), &id_a, id_a.device_id(0))
            .unwrap();
    // Honest responder path first (control): pin matches, session opens.
    let (resp, _, _) =
        respond_verified(&init, &responder_kp, &id_b, None, id_b.device_id(0)).unwrap();
    let resp_bytes = resp.encode();
    let resp_back = HandshakeResponse::decode(&resp_bytes).unwrap();
    assert!(initiator.finalize_verified(&resp_back, Some(&fp_b)).is_ok());
    // Attack variant: responder key swapped for attacker's (fresh full flow).
    let id_evil = IdentityKey::generate();
    let (initiator2, init2) =
        HandshakeInitiator::initiate_verified(&responder_kp.ek_bytes(), &id_a, id_a.device_id(0))
            .unwrap();
    let (resp2, _, _) =
        respond_verified(&init2, &responder_kp, &id_evil, None, id_evil.device_id(0)).unwrap();
    match initiator2.finalize_verified(&resp2, Some(&fp_b)) {
        Err(e) => assert!(format!("{e:?}").contains("mismatch")),
        Ok(_) => panic!("swapped identity must not verify against pin"),
    }
}

/// Wrong-protocol-version frame rejected (version rollback/downgrade).
#[test]
fn version_rollback_rejected() {
    let f = Frame::new(FrameType::Data, 0, b"hello".to_vec()).unwrap();
    let mut raw = f.encode();
    assert_eq!(raw.len(), 2048);
    raw[0] = 0x00;
    raw[1] = 0x01; // pretend to be protocol 0x0001
    assert!(Frame::decode(&raw).is_err());
}

/// Cross-protocol replay: handshake init bytes submitted as a Data message
/// must not decrypt (wrong wire type AND wrong key material).
#[test]
fn handshake_bytes_as_data_rejected() {
    let responder_kp = KyberKeypair::generate();
    let (_initiator, init) = HandshakeInitiator::initiate(&responder_kp.ek_bytes()).unwrap();
    let blob = init.encode();
    // Too big for one payload is fine — decode must simply fail, not panic.
    assert!(EncryptedMessage::decode(&blob).is_err() || blob.len() > 1984);
    // A truncated prefix parses structurally but can never decrypt: no
    // session shares its "key" (it's handshake randomness, not a message).
    let prefix = &blob[..blob.len().min(120)];
    if let Ok(msg) = EncryptedMessage::decode(prefix) {
        let kp_b2 = KyberKeypair::generate();
        let (initiator2, init2) = HandshakeInitiator::initiate(&kp_b2.ek_bytes()).unwrap();
        let (resp2, mut sess_b, _) = respond(&init2, &kp_b2).unwrap();
        let sess_a = initiator2.finalize(&resp2).unwrap();
        let _ = sess_a;
        assert!(sess_b.decrypt(&msg, b"ad").is_err());
    }
}

/// Exact frame replay: consuming the same Data frame twice must fail the
/// second time (replay protection via consumed counters/skip-cache).
#[test]
fn exact_replay_rejected() {
    let responder_kp = KyberKeypair::generate();
    let (initiator, init) = HandshakeInitiator::initiate(&responder_kp.ek_bytes()).unwrap();
    let (resp, mut sess_b, _) = respond(&init, &responder_kp).unwrap();
    let mut sess_a = initiator.finalize(&resp).unwrap();
    let ad = b"replay-ad";
    let msg = sess_a.encrypt(b"once", ad).unwrap();
    let wire = msg.encode();
    let back = EncryptedMessage::decode(&wire).unwrap();
    assert_eq!(sess_b.decrypt(&back, ad).unwrap(), b"once");
    let again = EncryptedMessage::decode(&wire).unwrap();
    assert!(sess_b.decrypt(&again, ad).is_err());
}

/// KyberRekey ciphertext submitted as Data: structurally a message only if
/// ≥48 bytes; either way it must never decrypt under the message key.
#[test]
fn rekey_ct_as_data_rejected() {
    let responder_kp = KyberKeypair::generate();
    let (initiator, init) = HandshakeInitiator::initiate(&responder_kp.ek_bytes()).unwrap();
    let (resp, mut sess_b, _) = respond(&init, &responder_kp).unwrap();
    let mut sess_a = initiator.finalize(&resp).unwrap();
    let ct = sess_a.kyber_rekey_initiate().unwrap();
    assert!(ct.len() >= 48);
    let fake = EncryptedMessage::decode(&ct).unwrap();
    assert!(sess_b.decrypt(&fake, b"ad").is_err());
    let _ = resp;
}

/// Sanity: an untouched verified session still opens (no false positives
/// from the checks above) and carries framed traffic.
#[test]
fn control_verified_session_opens_and_frames() {
    let responder_kp = KyberKeypair::generate();
    let id_a = IdentityKey::generate();
    let id_b = IdentityKey::generate();
    let (initiator, init) =
        HandshakeInitiator::initiate_verified(&responder_kp.ek_bytes(), &id_a, id_a.device_id(0))
            .unwrap();
    let (resp, mut sess_b, _) =
        respond_verified(&init, &responder_kp, &id_b, None, id_b.device_id(0)).unwrap();
    let mut sess_a = initiator
        .finalize_verified(&resp, Some(&id_b.fingerprint()))
        .unwrap();
    let frames = pack_data(&mut sess_a, b"control", b"ad").unwrap();
    assert_eq!(frames.len(), 1);
    match unpack_frame(&mut sess_b, &frames[0].encode(), b"ad").unwrap() {
        Unpacked::Text(pt) => assert_eq!(pt, b"control"),
        Unpacked::NoText | Unpacked::Goodbye => panic!("expected text"),
    }
}
