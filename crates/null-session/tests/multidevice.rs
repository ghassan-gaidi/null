//! Three-process multi-device flow (see `docs/multidevice.md`).
//!
//! - A1, A2: two devices, ONE identity (`id_a`, slots 0/1).
//! - B: one device, own identity.
//!
//! Proves: device-bound verified 1:1 sessions + fan-out to both of A's
//!   devices (each copy decrypts only under its own ek-bound AD); group
//!   join of all three device-members with agreeing message keys;
//!   revocation of A2 via TreeKEM removal (A2 excluded afterwards);
//!   DeviceSet fan-out shrinkage.

use null_crypto::{identity::IdentityKey, respond_verified, HandshakeInitiator, KyberKeypair};
use null_group::{Group, KeyPackage};
use null_identity::{device_member_id, DeviceSet};
use null_session::{ad_for_bytes, fanout_pack, unpack_frame, Fanout, Unpacked};

fn kp_for(member_id: [u8; 32]) -> (KeyPackage, KyberKeypair) {
    let kp = KyberKeypair::generate();
    let ek = kp.ek_bytes();
    (
        KeyPackage {
            member_id,
            kyber_ek: ek,
            signature_hint: None,
        },
        kp,
    )
}

#[test]
fn three_process_multidevice_flow() {
    // ---- identities & devices ----
    let id_a = IdentityKey::generate();
    let id_b = IdentityKey::generate();
    let fp_a = id_a.fingerprint();
    let fp_b = id_b.fingerprint();
    let d_a1 = id_a.device_id(0);
    let d_a2 = id_a.device_id(1);
    let d_b = id_b.device_id(0);
    assert_ne!(d_a1, d_a2);

    // Device roster for A (fan-out set + group member ids).
    let mut set_a = DeviceSet::new(fp_a.clone());
    let kp_a1 = KyberKeypair::generate();
    let kp_a2 = KyberKeypair::generate();
    set_a.add_device(d_a1, kp_a1.ek_bytes()).unwrap();
    set_a.add_device(d_a2, kp_a2.ek_bytes()).unwrap();
    assert_eq!(set_a.active_count(), 2);

    // ---- 1:1 verified sessions A1↔B and A2↔B, device-bound ----
    let kp_b = KyberKeypair::generate();
    let (initiator1, init1) =
        HandshakeInitiator::initiate_verified(&kp_b.ek_bytes(), &id_a, d_a1).unwrap();
    let (resp1, mut sess_b1, _) = respond_verified(&init1, &kp_b, &id_b, None, d_b).unwrap();
    let mut sess_a1 = initiator1.finalize_verified(&resp1, Some(&fp_b)).unwrap();

    let (initiator2, init2) =
        HandshakeInitiator::initiate_verified(&kp_b.ek_bytes(), &id_a, d_a2).unwrap();
    let (resp2, mut sess_b2, _) = respond_verified(&init2, &kp_b, &id_b, None, d_b).unwrap();
    let mut sess_a2 = initiator2.finalize_verified(&resp2, Some(&fp_b)).unwrap();

    // B fans one message out to both of A's devices; each copy carries its
    // own ek-bound AD and decrypts only under its own session.
    let ads = [
        ad_for_bytes(&kp_b.ek_bytes(), &kp_a1.ek_bytes()),
        ad_for_bytes(&kp_b.ek_bytes(), &kp_a2.ek_bytes()),
    ];
    let mut targets = [
        Fanout {
            session: &mut sess_b1,
            ad: ads[0].clone(),
        },
        Fanout {
            session: &mut sess_b2,
            ad: ads[1].clone(),
        },
    ];
    let batches = fanout_pack(&mut targets, b"hello both devices").unwrap();
    assert_eq!(batches.len(), 2);
    drop(targets);
    for (frames, sess_a, ad) in [
        (&batches[0], &mut sess_a1, &ads[0]),
        (&batches[1], &mut sess_a2, &ads[1]),
    ] {
        assert_eq!(frames.len(), 1);
        match unpack_frame(sess_a, &frames[0].encode(), ad).unwrap() {
            Unpacked::Text(pt) => assert_eq!(pt, b"hello both devices"),
            Unpacked::NoText | Unpacked::Goodbye => panic!("expected text"),
        }
    }
    // Cross-decryption is impossible by construction: batch[0] under ad[1]
    // fails (wrong AD binds a different key).
    match unpack_frame(&mut sess_a2, &batches[0][0].encode(), &ads[1]) {
        Ok(Unpacked::Text(_)) => panic!("cross-device decrypt must fail"),
        Ok(Unpacked::NoText) | Ok(Unpacked::Goodbye) => {
            panic!("expected hard decrypt failure, not silent drop")
        }
        Err(_) => {}
    }

    // ---- group with all three device-members ----
    let m_a1 = device_member_id(&fp_a, &d_a1);
    let m_a2 = device_member_id(&fp_a, &d_a2);
    let m_b = device_member_id(&fp_b, &d_b);
    let (kp_m_a1, dk_m_a1) = kp_for(m_a1);
    let (kp_m_a2, dk_m_a2) = kp_for(m_a2);
    let (kp_m_b, dk_m_b) = kp_for(m_b);
    let mut g_creator = Group::create();
    let (w_a1, _c1) = g_creator.add(kp_m_a1).unwrap();
    let mut g_a1 = Group::join(&w_a1, m_a1, &dk_m_a1).unwrap();
    let (w_a2, c_a2) = g_creator.add(kp_m_a2).unwrap();
    g_a1.process_commit(&c_a2).unwrap();
    let mut g_a2 = Group::join(&w_a2, m_a2, &dk_m_a2).unwrap();
    let (w_b, c_b) = g_creator.add(kp_m_b).unwrap();
    g_a1.process_commit(&c_b).unwrap();
    g_a2.process_commit(&c_b).unwrap();
    let mut g_b = Group::join(&w_b, m_b, &dk_m_b).unwrap();
    // Creator + three device-members.
    assert_eq!(g_creator.member_count(), 4);

    // All three derive identical group message keys.
    let sender = [0x77u8; 32];
    let k_creator = g_creator.message_key(&sender).unwrap();
    assert_eq!(g_a1.message_key(&sender).unwrap(), k_creator);
    assert_eq!(g_a2.message_key(&sender).unwrap(), k_creator);
    assert_eq!(g_b.message_key(&sender).unwrap(), k_creator);

    // ---- revoke device A2 ----
    set_a.revoke(&d_a2).unwrap();
    assert_eq!(set_a.active_count(), 1);
    assert_eq!(set_a.active_devices().len(), 1);
    let commit_rm = g_creator.remove(&m_a2).unwrap();
    g_b.process_commit(&commit_rm).unwrap();
    g_a1.process_commit(&commit_rm).unwrap();
    // A2 (removed) cannot follow the next epoch: sealed to others only.
    let upd = g_creator.update().unwrap();
    g_b.process_commit(&upd).unwrap();
    g_a1.process_commit(&upd).unwrap();
    assert!(g_a2.process_commit(&upd).is_err());
    // Remaining members still agree. Use a fresh probe sender so all
    // chains start at seq 0 and the keys are directly comparable.
    let probe = [0xABu8; 32];
    let kc = g_creator.message_key(&probe).unwrap();
    assert_eq!(g_b.message_key(&probe).unwrap(), kc);
    assert_eq!(g_a1.message_key(&probe).unwrap(), kc);
    // NOTE: no further comparison with the pre-revocation `sender` chain:
    // commit processing prunes non-roster sender chains on recipients while
    // the committer (who never processes its own commits) retains them, so
    // sequence numbers legitimately differ there. Fresh senders compare
    // exactly, which is what the probe asserts above prove.
}
