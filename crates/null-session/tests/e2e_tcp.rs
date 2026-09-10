//! Full initiator↔responder run over real TCP sockets: fragmented
//! handshake, ek-bound AD, shaped frames, bidirectional chat, PQ rekey.
//! This is the same code path the `null` binary uses for live peers.

use null_core::TransportKind;
use null_crypto::{
    identity::IdentityKey, respond, respond_verified, HandshakeInitiator, KyberKeypair,
};
use null_identity::safety_number;
use null_session::{
    ad_for_bytes, pack_data, pack_handshake_init, pack_handshake_response, unpack_frame,
    HandshakeMsg, HandshakeReassembler, Unpacked,
};
use null_transport::{Endpoint, TransportConn};

fn conn(stream: tokio::net::TcpStream) -> TransportConn {
    TransportConn::new_live(
        TransportKind::Tor,
        Endpoint {
            onion_host: "test".into(),
            port: 80,
        },
        stream,
    )
}

#[tokio::test]
async fn tcp_handshake_and_chat() {
    let kp_b = KyberKeypair::generate();
    let ek_b = kp_b.ek_bytes();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let responder = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut c = conn(stream);
        // Reassemble fragmented init.
        let mut re = HandshakeReassembler::new();
        let init = loop {
            let raw = c.recv_blob().await.unwrap();
            match re.add_raw(&raw).unwrap() {
                Some(HandshakeMsg::Init(i)) => break i,
                _ => continue,
            }
        };
        let (resp, mut sess_b, _) = respond(&init, &kp_b).unwrap();
        for f in pack_handshake_response(&resp).unwrap() {
            c.send_blob(&f.encode()).await.unwrap();
        }
        // Ek-bound AD: responder's out = (own, peer).
        let ad_out = ad_for_bytes(&kp_b.ek_bytes(), &init.kyber_ek);
        let ad_in = ad_for_bytes(&init.kyber_ek, &kp_b.ek_bytes());
        // Receive initiator text, reply.
        let raw = c.recv_blob().await.unwrap();
        let text = match unpack_frame(&mut sess_b, &raw, &ad_in).unwrap() {
            Unpacked::Text(pt) => pt,
            Unpacked::NoText | Unpacked::Goodbye => panic!("expected text"),
        };
        assert_eq!(text, b"hello responder");
        for f in pack_data(&mut sess_b, b"hello initiator", &ad_out).unwrap() {
            c.send_blob(&f.encode()).await.unwrap();
        }
        // Safety numbers must match across the wire.
        let sn_b = safety_number(&kp_b.ek_bytes(), &init.kyber_ek, b"e2e");
        (sn_b, sess_b.kyber_ek_bytes())
    });

    // Initiator side.
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut c = conn(stream);
    let (init, init_msg) = HandshakeInitiator::initiate(&ek_b).unwrap();
    let own_ek = init.own_kyber.ek_bytes();
    for f in pack_handshake_init(&init_msg).unwrap() {
        c.send_blob(&f.encode()).await.unwrap();
    }
    let mut re = HandshakeReassembler::new();
    let resp = loop {
        let raw = c.recv_blob().await.unwrap();
        match re.add_raw(&raw).unwrap() {
            Some(HandshakeMsg::Response(r)) => break r,
            _ => continue,
        }
    };
    let mut sess_a = init.finalize(&resp).unwrap();
    let ad_out = ad_for_bytes(&own_ek, &ek_b);
    let ad_in = ad_for_bytes(&ek_b, &own_ek);
    for f in pack_data(&mut sess_a, b"hello responder", &ad_out).unwrap() {
        c.send_blob(&f.encode()).await.unwrap();
    }
    let raw = c.recv_blob().await.unwrap();
    match unpack_frame(&mut sess_a, &raw, &ad_in).unwrap() {
        Unpacked::Text(pt) => assert_eq!(pt, b"hello initiator"),
        Unpacked::NoText | Unpacked::Goodbye => panic!("expected reply"),
    }
    let sn_a = safety_number(&own_ek, &ek_b, b"e2e");

    let (sn_b, _) = responder.await.unwrap();
    assert_eq!(sn_a, sn_b);
}

/// Verified mode over TCP: ML-DSA-65 signatures both ways, fingerprint
/// pinning, vk-bound safety numbers, then encrypted chat.
#[tokio::test]
async fn tcp_verified_handshake_and_chat() {
    let kp_b = KyberKeypair::generate();
    let ek_b = kp_b.ek_bytes();
    let id_b = IdentityKey::generate();
    let fp_b = id_b.fingerprint();
    let vk_b = id_b.verifying_bytes();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let vk_b2 = vk_b.clone();
    let responder = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut c = conn(stream);
        let mut re = HandshakeReassembler::new();
        let init = loop {
            let raw = c.recv_blob().await.unwrap();
            match re.add_raw(&raw).unwrap() {
                Some(HandshakeMsg::Init(i)) => break i,
                _ => continue,
            }
        };
        let (resp, mut sess_b, _) =
            respond_verified(&init, &kp_b, &id_b, None, id_b.device_id(0)).unwrap();
        for f in pack_handshake_response(&resp).unwrap() {
            c.send_blob(&f.encode()).await.unwrap();
        }
        let vk_a = init.identity_vk.clone().unwrap();
        let ad_in = ad_for_bytes(&vk_a, &vk_b2);
        let raw = c.recv_blob().await.unwrap();
        match unpack_frame(&mut sess_b, &raw, &ad_in).unwrap() {
            Unpacked::Text(pt) => assert_eq!(pt, b"verified hello"),
            Unpacked::NoText | Unpacked::Goodbye => panic!("expected text"),
        }
        safety_number(&vk_b2, &vk_a, b"e2e-verified")
    });

    let id_a = IdentityKey::generate();
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut c = conn(stream);
    let (init, init_msg) =
        HandshakeInitiator::initiate_verified(&ek_b, &id_a, id_a.device_id(0)).unwrap();
    let own_vk = id_a.verifying_bytes();
    for f in pack_handshake_init(&init_msg).unwrap() {
        c.send_blob(&f.encode()).await.unwrap();
    }
    let mut re = HandshakeReassembler::new();
    let resp = loop {
        let raw = c.recv_blob().await.unwrap();
        match re.add_raw(&raw).unwrap() {
            Some(HandshakeMsg::Response(r)) => break r,
            _ => continue,
        }
    };
    let mut sess_a = init.finalize_verified(&resp, Some(&fp_b)).unwrap();
    let ad_out = ad_for_bytes(&own_vk, &vk_b);
    for f in pack_data(&mut sess_a, b"verified hello", &ad_out).unwrap() {
        c.send_blob(&f.encode()).await.unwrap();
    }
    let sn_a = safety_number(&own_vk, &vk_b, b"e2e-verified");
    assert_eq!(sn_a, responder.await.unwrap());
}
