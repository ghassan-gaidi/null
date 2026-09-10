//! Null Triple Ratchet (NTR) — SUMMARY.md §4.
//!
//! Combines Triple Diffie-Hellman (deniable by default) with
//! ML-KEM-1024 (Kyber-1024, FIPS 203) and a per-message symmetric
//! ratchet (HKDF-SHA384 + ChaCha20-Poly1305).
//!
//! Security bounds (§4.4):
//! - Classical PCS after 1 message (ECDH ratchet).
//! - Quantum PCS after Kyber re-encap (≤50 msgs / 7 days).
//! - Forward secrecy via one-way chain evolution.

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use null_core::{NullError, Result, KYBER_REKEY_INTERVAL_MSGS, KYBER_REKEY_INTERVAL_SECS};
use rand::rngs::OsRng;
use sha2::Sha384;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// ECDH helpers
// ---------------------------------------------------------------------------

/// Ephemeral X25519 keypair (per-message ratchet, §4.2).
pub struct EphemeralKey {
    secret: StaticSecret,
    public: PublicKey,
}

impl EphemeralKey {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> [u8; 32] {
        let peer_pk = PublicKey::from(*peer);
        *self.secret.diffie_hellman(&peer_pk).as_bytes()
    }
}

impl Drop for EphemeralKey {
    fn drop(&mut self) {
        // StaticSecret zeroizes on drop already; belt-and-braces.
    }
}

// ---------------------------------------------------------------------------
// Kyber (ML-KEM-1024) wrapper
// ---------------------------------------------------------------------------

use kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024};

pub type MlKem1024Ek = <MlKem1024 as KemCore>::EncapsulationKey;
pub type MlKem1024Dk = <MlKem1024 as KemCore>::DecapsulationKey;
pub type MlKem1024Ct = ml_kem::Ciphertext<MlKem1024>;

#[derive(Clone)]
pub struct KyberKeypair {
    pub ek: MlKem1024Ek,
    pub dk: MlKem1024Dk,
}

impl KyberKeypair {
    pub fn generate() -> Self {
        let (dk, ek) = MlKem1024::generate(&mut OsRng);
        Self { ek, dk }
    }

    pub fn encapsulate(&self) -> (Vec<u8>, Vec<u8>) {
        let (ct, k) = self.ek.encapsulate(&mut OsRng).expect("kyber encapsulate");
        (ct.as_slice().to_vec(), k.as_slice().to_vec())
    }

    pub fn decapsulate(&self, ct_bytes: &[u8]) -> Result<Vec<u8>> {
        use hybrid_array::Array;
        let ct: MlKem1024Ct = Array::try_from(ct_bytes)
            .map_err(|_| NullError::Crypto(format!("bad kyber ct len {}", ct_bytes.len())))?;
        let k = self
            .dk
            .decapsulate(&ct)
            .map_err(|e| NullError::Crypto(format!("decap: {e:?}")))?;
        Ok(k.as_slice().to_vec())
    }

    pub fn ek_bytes(&self) -> Vec<u8> {
        self.ek.as_bytes().as_slice().to_vec()
    }
}

/// One-shot encapsulate to a raw ek blob (for handshake / rekey frames).
pub fn kyber_encap_to(ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use hybrid_array::Array;
    let ek_arr: Encoded<MlKem1024Ek> = Array::try_from(ek_bytes)
        .map_err(|_| NullError::Crypto(format!("bad kyber ek len {}", ek_bytes.len())))?;
    let ek = MlKem1024Ek::from_bytes(&ek_arr);
    let (ct, k) = ek.encapsulate(&mut OsRng).expect("kyber encapsulate");
    Ok((ct.as_slice().to_vec(), k.as_slice().to_vec()))
}

// ---------------------------------------------------------------------------
// HKDF-SHA384 helpers
// ---------------------------------------------------------------------------

fn hkdf_sha384(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha384>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm).expect("hkdf expand");
    okm
}

pub fn initial_root_key(dh3: &[u8; 32], k_kyber: &[u8]) -> [u8; 48] {
    let mut ikm = Vec::with_capacity(32 + k_kyber.len());
    ikm.extend_from_slice(dh3);
    ikm.extend_from_slice(k_kyber);
    let salt = [0u8; 48];
    let okm = hkdf_sha384(&ikm, &salt, b"Null-v2.0-initial-root-key", 48);
    let mut out = [0u8; 48];
    out.copy_from_slice(&okm);
    out
}

// ---------------------------------------------------------------------------
// Handshake (§4.1)
// ---------------------------------------------------------------------------

/// Outgoing handshake blob: `EK_A.pub ‖ kyber_ct ‖ kyber_ek_A ‖ optional_sig`.
#[derive(Debug, Clone)]
pub struct HandshakeInit {
    pub ephemeral_pub: [u8; 32],
    pub kyber_ct: Vec<u8>,
    /// Initiator's long-term Kyber ek so the responder can re-encapsulate
    /// to it during later ratchet rekeys (§4.2).
    pub kyber_ek: Vec<u8>,
    /// Initiator's ML-DSA-65 vk (verified mode only).
    pub identity_vk: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
}

/// Optional verified identity: ML-DSA-65 signatures (FIPS 204) over the
/// handshake transcript (§4.3). Default mode stays deniable (no signatures).
pub mod identity {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Seed, SigningKey, VerifyingKey};
    use null_core::{NullError, Result};
    use rand::{rngs::OsRng, RngCore};
    use sha3::{Digest, Sha3_256};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    const CTX: &[u8] = b"Null-v2.0-handshake";

    /// Long-term identity key. Only the 32B seed is stored (wiped on drop);
    /// signing/verification keys are derived transiently per operation.
    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct IdentityKey {
        seed: [u8; 32],
    }

    impl IdentityKey {
        pub fn generate() -> Self {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            Self { seed }
        }

        fn signing_key(&self) -> SigningKey<MlDsa65> {
            SigningKey::<MlDsa65>::from_seed(&Seed::from(self.seed))
        }

        /// Raw 1952B verification key bytes for exchange + fingerprinting.
        pub fn verifying_bytes(&self) -> Vec<u8> {
            self.signing_key()
                .expanded_key()
                .verifying_key()
                .encode()
                .to_vec()
        }

        /// `ml-dsa:<hex(sha3_256(vk))>` fingerprint for `null://` strings.
        pub fn fingerprint(&self) -> String {
            fingerprint_hex(&self.verifying_bytes())
        }

        pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
            let sig = self
                .signing_key()
                .expanded_key()
                .sign_deterministic(msg, CTX)
                .map_err(|_| NullError::Crypto("mldsa sign failed".into()))?;
            Ok(sig.encode().to_vec())
        }

        pub fn verify(vk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
            let vk_arr: EncodedVerifyingKey<MlDsa65> = vk_bytes
                .try_into()
                .map_err(|_| NullError::Crypto("bad mldsa vk length".into()))?;
            let vk = VerifyingKey::<MlDsa65>::decode(&vk_arr);
            let sig_arr: EncodedSignature<MlDsa65> = sig_bytes
                .try_into()
                .map_err(|_| NullError::Crypto("bad mldsa sig length".into()))?;
            let sig = ml_dsa::Signature::<MlDsa65>::decode(&sig_arr)
                .ok_or_else(|| NullError::Crypto("bad mldsa sig encoding".into()))?;
            if vk.verify_with_context(msg, CTX, &sig) {
                Ok(())
            } else {
                Err(NullError::Crypto("mldsa signature invalid".into()))
            }
        }
    }

    /// Fingerprint for a raw vk blob (verifies `i=` params without a key).
    pub fn fingerprint_hex(vk_bytes: &[u8]) -> String {
        let mut h = Sha3_256::new();
        h.update(vk_bytes);
        format!("ml-dsa:{}", hex_of(&h.finalize()))
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sign_verify_roundtrip() {
            let id = IdentityKey::generate();
            let vk = id.verifying_bytes();
            assert_eq!(vk.len(), 1952);
            let sig = id.sign(b"transcript").unwrap();
            IdentityKey::verify(&vk, b"transcript", &sig).unwrap();
            assert!(IdentityKey::verify(&vk, b"tampered", &sig).is_err());
            assert!(IdentityKey::verify(&vk, b"transcript", b"short").is_err());
            let fp = id.fingerprint();
            assert!(fp.starts_with("ml-dsa:"));
            assert_eq!(fp, fingerprint_hex(&vk));
        }
    }
}

/// Responder reply: `EK_B.pub ‖ kyber_ek_B ‖ vk_B ‖ sig_B`.
#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub ephemeral_pub: [u8; 32],
    /// Responder's long-term Kyber ek (echo of the advertised key).
    pub kyber_ek: Vec<u8>,
    /// Responder's ML-DSA-65 vk (verified mode only).
    pub identity_vk: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
}

fn put_blob(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

fn get_blob(mut bytes: &[u8]) -> Result<(Vec<u8>, &[u8])> {
    if bytes.len() < 2 {
        return Err(NullError::Crypto("handshake blob truncated".into()));
    }
    let n = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    bytes = &bytes[2..];
    if bytes.len() < n {
        return Err(NullError::Crypto("handshake blob overrun".into()));
    }
    Ok((bytes[..n].to_vec(), &bytes[n..]))
}

fn put_sig(out: &mut Vec<u8>, sig: &Option<Vec<u8>>) {
    match sig {
        Some(s) => {
            out.push(1);
            put_blob(out, s);
        }
        None => out.push(0),
    }
}

fn get_sig(mut bytes: &[u8]) -> Result<(Option<Vec<u8>>, &[u8])> {
    if bytes.is_empty() {
        return Err(NullError::Crypto("handshake sig flag missing".into()));
    }
    let flag = bytes[0];
    bytes = &bytes[1..];
    match flag {
        0 => Ok((None, bytes)),
        1 => {
            let (s, rest) = get_blob(bytes)?;
            Ok((Some(s), rest))
        }
        _ => Err(NullError::Crypto("bad handshake sig flag".into())),
    }
}

impl HandshakeInit {
    /// Wire: `eph(32) ‖ ek_blob ‖ ct_blob ‖ vk_opt ‖ sig`.
    /// `vk_opt`: flag(1: 0/1) ‖ vk_blob?.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.ephemeral_pub);
        put_blob(&mut out, &self.kyber_ek);
        put_blob(&mut out, &self.kyber_ct);
        match &self.identity_vk {
            Some(vk) => {
                out.push(1);
                put_blob(&mut out, vk);
            }
            None => out.push(0),
        }
        put_sig(&mut out, &self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 32 {
            return Err(NullError::Crypto("handshake init too short".into()));
        }
        let mut ephemeral_pub = [0u8; 32];
        ephemeral_pub.copy_from_slice(&bytes[..32]);
        let (kyber_ek, rest) = get_blob(&bytes[32..])?;
        let (kyber_ct, rest) = get_blob(rest)?;
        if rest.is_empty() {
            return Err(NullError::Crypto("handshake init missing vk flag".into()));
        }
        let (identity_vk, rest) = match rest[0] {
            0 => (None, &rest[1..]),
            1 => {
                let (vk, r) = get_blob(&rest[1..])?;
                (Some(vk), r)
            }
            _ => return Err(NullError::Crypto("bad handshake vk flag".into())),
        };
        let (signature, rest) = get_sig(rest)?;
        if !rest.is_empty() {
            return Err(NullError::Crypto("handshake init trailing bytes".into()));
        }
        Ok(Self {
            ephemeral_pub,
            kyber_ct,
            kyber_ek,
            identity_vk,
            signature,
        })
    }

    /// Transcript bytes covered by the initiator's ML-DSA signature.
    pub fn signing_msg(&self) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&self.ephemeral_pub);
        m.extend_from_slice(&self.kyber_ct);
        m.extend_from_slice(&self.kyber_ek);
        if let Some(vk) = &self.identity_vk {
            m.extend_from_slice(vk);
        }
        m
    }
}

impl HandshakeResponse {
    /// Wire: `eph(32) ‖ ek_blob ‖ vk_opt ‖ sig`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.ephemeral_pub);
        put_blob(&mut out, &self.kyber_ek);
        match &self.identity_vk {
            Some(vk) => {
                out.push(1);
                put_blob(&mut out, vk);
            }
            None => out.push(0),
        }
        put_sig(&mut out, &self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 32 {
            return Err(NullError::Crypto("handshake response too short".into()));
        }
        let mut ephemeral_pub = [0u8; 32];
        ephemeral_pub.copy_from_slice(&bytes[..32]);
        let (kyber_ek, rest) = get_blob(&bytes[32..])?;
        if rest.is_empty() {
            return Err(NullError::Crypto(
                "handshake response missing vk flag".into(),
            ));
        }
        let (identity_vk, rest) = match rest[0] {
            0 => (None, &rest[1..]),
            1 => {
                let (vk, r) = get_blob(&rest[1..])?;
                (Some(vk), r)
            }
            _ => return Err(NullError::Crypto("bad handshake vk flag".into())),
        };
        let (signature, rest) = get_sig(rest)?;
        if !rest.is_empty() {
            return Err(NullError::Crypto(
                "handshake response trailing bytes".into(),
            ));
        }
        Ok(Self {
            ephemeral_pub,
            kyber_ek,
            identity_vk,
            signature,
        })
    }

    /// Transcript bytes covered by the responder's ML-DSA signature.
    pub fn signing_msg(&self, init_eph: &[u8; 32], init_ct: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(init_eph);
        m.extend_from_slice(&self.ephemeral_pub);
        m.extend_from_slice(init_ct);
        if let Some(vk) = &self.identity_vk {
            m.extend_from_slice(vk);
        }
        m
    }
}

/// Initiator state kept between init/response.
pub struct HandshakeInitiator {
    pub ek_a: EphemeralKey,
    pub k_kyber: Vec<u8>,
    pub own_kyber: KyberKeypair,
    pub peer_kyber_ek: Vec<u8>,
    init_ct: Vec<u8>,
}

impl HandshakeInitiator {
    /// 3DH (deniable: DH1/DH2 omitted) + Kyber encap to peer ek.
    pub fn initiate(peer_kyber_ek: &[u8]) -> Result<(Self, HandshakeInit)> {
        let ek_a = EphemeralKey::generate();
        let own_kyber = KyberKeypair::generate();
        let (ct, k_kyber) = kyber_encap_to(peer_kyber_ek)?;
        let init = HandshakeInit {
            ephemeral_pub: ek_a.public_bytes(),
            kyber_ct: ct.clone(),
            kyber_ek: own_kyber.ek_bytes(),
            identity_vk: None,
            signature: None, // deniable default
        };
        Ok((
            Self {
                ek_a,
                k_kyber,
                own_kyber,
                peer_kyber_ek: peer_kyber_ek.to_vec(),
                init_ct: ct,
            },
            init,
        ))
    }

    /// Verified mode (§4.3): attach our ML-DSA-65 vk + signature.
    pub fn initiate_verified(
        peer_kyber_ek: &[u8],
        id: &identity::IdentityKey,
    ) -> Result<(Self, HandshakeInit)> {
        let (state, mut init) = Self::initiate(peer_kyber_ek)?;
        init.identity_vk = Some(id.verifying_bytes());
        init.signature = Some(id.sign(&init.signing_msg())?);
        Ok((state, init))
    }

    pub fn finalize(self, resp: &HandshakeResponse) -> Result<Session> {
        let dh3 = self.ek_a.diffie_hellman(&resp.ephemeral_pub);
        let root = initial_root_key(&dh3, &self.k_kyber);
        Ok(Session::new_from_handshake(
            root,
            self.ek_a,
            resp.ephemeral_pub,
            self.k_kyber,
            self.own_kyber,
            // Prefer the live echo; fall back to the advertised key.
            if resp.kyber_ek.is_empty() {
                self.peer_kyber_ek
            } else {
                resp.kyber_ek.clone()
            },
        ))
    }

    /// Verified finalize: checks the responder's ML-DSA signature and,
    /// when `expected_fp` is `Some`, pins its vk fingerprint (TOFU otherwise).
    pub fn finalize_verified(
        self,
        resp: &HandshakeResponse,
        expected_fp: Option<&str>,
    ) -> Result<Session> {
        let vk = resp.identity_vk.as_ref().ok_or_else(|| {
            NullError::Crypto("verified mode: responder sent no identity vk".into())
        })?;
        let sig = resp.signature.as_ref().ok_or_else(|| {
            NullError::Crypto("verified mode: responder sent no signature".into())
        })?;
        let transcript = resp.signing_msg(&self.ek_a.public_bytes(), &self.init_ct);
        identity::IdentityKey::verify(vk, &transcript, sig)?;
        if let Some(fp) = expected_fp {
            let got = identity::fingerprint_hex(vk);
            if got != fp {
                return Err(NullError::Crypto(format!(
                    "identity fingerprint mismatch: got {got}, want {fp}"
                )));
            }
        }
        self.finalize(resp)
    }
}

/// Responder side: decaps + generate EK_B.
pub fn respond(
    init: &HandshakeInit,
    kyber_longterm: &KyberKeypair,
) -> Result<(HandshakeResponse, Session, Vec<u8>)> {
    respond_inner(init, kyber_longterm, None)
}

/// Verified responder (§4.3): checks the initiator's ML-DSA signature, then
/// signs the transcript with our identity key.
pub fn respond_verified(
    init: &HandshakeInit,
    kyber_longterm: &KyberKeypair,
    id: &identity::IdentityKey,
    expected_fp: Option<&str>,
) -> Result<(HandshakeResponse, Session, Vec<u8>)> {
    let vk = init
        .identity_vk
        .as_ref()
        .ok_or_else(|| NullError::Crypto("verified mode: initiator sent no identity vk".into()))?;
    let sig = init
        .signature
        .as_ref()
        .ok_or_else(|| NullError::Crypto("verified mode: initiator sent no signature".into()))?;
    // Rebuild the initiator transcript exactly as it signed it.
    let probe = HandshakeInit {
        ephemeral_pub: init.ephemeral_pub,
        kyber_ct: init.kyber_ct.clone(),
        kyber_ek: init.kyber_ek.clone(),
        identity_vk: init.identity_vk.clone(),
        signature: None,
    };
    identity::IdentityKey::verify(vk, &probe.signing_msg(), sig)?;
    if let Some(fp) = expected_fp {
        let got = identity::fingerprint_hex(vk);
        if got != fp {
            return Err(NullError::Crypto(format!(
                "identity fingerprint mismatch: got {got}, want {fp}"
            )));
        }
    }
    respond_inner(init, kyber_longterm, Some(id))
}

fn respond_inner(
    init: &HandshakeInit,
    kyber_longterm: &KyberKeypair,
    id: Option<&identity::IdentityKey>,
) -> Result<(HandshakeResponse, Session, Vec<u8>)> {
    let k_kyber = kyber_longterm.decapsulate(&init.kyber_ct)?;
    let ek_b = EphemeralKey::generate();
    let dh3 = ek_b.diffie_hellman(&init.ephemeral_pub);
    let root = initial_root_key(&dh3, &k_kyber);
    let peer_pub = init.ephemeral_pub;
    let resp_pub = ek_b.public_bytes();
    let mut resp = HandshakeResponse {
        ephemeral_pub: resp_pub,
        kyber_ek: kyber_longterm.ek_bytes(),
        identity_vk: None,
        signature: None,
    };
    if let Some(idkey) = id {
        resp.identity_vk = Some(idkey.verifying_bytes());
        let transcript = resp.signing_msg(&init.ephemeral_pub, &init.kyber_ct);
        resp.signature = Some(idkey.sign(&transcript)?);
    }
    let session = Session::new_from_handshake(
        root,
        ek_b,
        peer_pub,
        k_kyber.clone(),
        kyber_longterm.clone(),
        init.kyber_ek.clone(),
    );
    Ok((resp, session, k_kyber))
}

// ---------------------------------------------------------------------------
// Triple-ratchet session (§4.2)
// ---------------------------------------------------------------------------

/// quirks: root/chain are 48 bytes (SHA384 output); message keys 32 bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SessionSecrets {
    #[zeroize(skip)]
    send_counter: u64,
    #[zeroize(skip)]
    recv_counter: u64,
    #[zeroize(skip)]
    msgs_since_kyber: u64,
    root_key: [u8; 48],
    chain_key: [u8; 48],
    #[zeroize(skip)]
    ecdh_secret: EphemeralKeyPlaceholder,
    kyber_shared: Vec<u8>,
}

/// X25519 secret can't derive Zeroize easily; keep raw bytes.
#[derive(Clone)]
struct EphemeralKeyPlaceholder {
    secret_bytes: [u8; 32],
}

impl Zeroize for EphemeralKeyPlaceholder {
    fn zeroize(&mut self) {
        self.secret_bytes.zeroize();
    }
}

pub struct Session {
    secrets: SessionSecrets,
    ecdh_ratchet: EphemeralKey,
    peer_ecdh_pub: Option<[u8; 32]>,
    /// Own long-term Kyber pair (stable for the session lifetime; the peer
    /// re-encapsulates to its ek on every PQ rekey, §4.2).
    kyber_longterm: KyberKeypair,
    /// Peer's long-term Kyber ek (encap target for our rekeys).
    peer_kyber_ek: Vec<u8>,
    /// PQ rekey generation: incremented on every root mix (initiate or
    /// receive). Carried on each message so loss is detectable.
    kyber_generation: u64,
    /// Recent rekeys WE initiated: (generation, ct, shared secret), newest
    /// last, capped — replayed on REKEY_REQUEST so a peer that lost our
    /// rekey frames can still heal without re-handshaking.
    retained_rekeys: std::collections::VecDeque<(u64, Vec<u8>, Vec<u8>)>,
    /// Cached chain keys for skipped counters (out-of-order delivery).
    /// Bounded by MAX_SKIP; wiped on drop.
    skipped: HashMap<u64, [u8; 48]>,
    last_kyber_rekey: Instant,
    #[allow(dead_code)]
    created_at: Instant,
}

/// Max forward jump / cached keys for out-of-order frames.
pub const MAX_SKIP: u64 = 200;

/// How many initiated rekeys are retained for loss recovery.
pub const RETAINED_REKEYS: usize = 8;

impl Drop for Session {
    fn drop(&mut self) {
        for (_, k) in self.skipped.iter_mut() {
            k.zeroize();
        }
        self.skipped.clear();
        for (_, _, k) in self.retained_rekeys.iter_mut() {
            k.zeroize();
        }
        self.retained_rekeys.clear();
    }
}

impl Session {
    /// Build from handshake material: deterministic chain from root so both
    /// peers converge; ECDH ratchet seeded with handshake ephemeral.
    pub fn new_from_handshake(
        root: [u8; 48],
        our_ephemeral: EphemeralKey,
        peer_pub: [u8; 32],
        kyber_shared: Vec<u8>,
        kyber_longterm: KyberKeypair,
        peer_kyber_ek: Vec<u8>,
    ) -> Self {
        let chain = hkdf_sha384(&root, &[0u8; 48], b"Null-v2.0-chain-init", 48);
        let mut c = [0u8; 48];
        c.copy_from_slice(&chain);
        Self {
            secrets: SessionSecrets {
                send_counter: 0,
                recv_counter: 0,
                msgs_since_kyber: 0,
                root_key: root,
                chain_key: c,
                ecdh_secret: EphemeralKeyPlaceholder {
                    secret_bytes: [0u8; 32],
                },
                kyber_shared,
            },
            ecdh_ratchet: our_ephemeral,
            peer_ecdh_pub: Some(peer_pub),
            kyber_longterm,
            peer_kyber_ek,
            kyber_generation: 0,
            retained_rekeys: std::collections::VecDeque::new(),
            skipped: HashMap::new(),
            last_kyber_rekey: Instant::now(),
            created_at: Instant::now(),
        }
    }

    /// Legacy constructor (tests / group contexts without handshake pubs).
    /// Peer's ek defaults to our own so self-rekey roundtrips work.
    pub fn new_from_root(root: [u8; 48]) -> Self {
        let chain = hkdf_sha384(&root, &[0u8; 48], b"Null-v2.0-chain-init", 48);
        let mut c = [0u8; 48];
        c.copy_from_slice(&chain);
        let kp = KyberKeypair::generate();
        let peer_ek = kp.ek_bytes();
        Self {
            secrets: SessionSecrets {
                send_counter: 0,
                recv_counter: 0,
                msgs_since_kyber: 0,
                root_key: root,
                chain_key: c,
                ecdh_secret: EphemeralKeyPlaceholder {
                    secret_bytes: [0u8; 32],
                },
                kyber_shared: vec![0u8; 32],
            },
            ecdh_ratchet: EphemeralKey::generate(),
            peer_ecdh_pub: None,
            kyber_longterm: kp,
            peer_kyber_ek: peer_ek,
            kyber_generation: 0,
            retained_rekeys: std::collections::VecDeque::new(),
            skipped: HashMap::new(),
            last_kyber_rekey: Instant::now(),
            created_at: Instant::now(),
        }
    }

    /// For tests: two sessions from the same root converge to the same
    /// chain by reseeding. In production both sides derive from handshake
    /// root only — chain init uses HKDF(root, fixed) so both match.
    pub fn new_deterministic_for_test(root: [u8; 48]) -> (Self, Self) {
        (Self::new_from_root(root), Self::new_from_root(root))
    }

    pub fn kyber_ek_bytes(&self) -> Vec<u8> {
        self.kyber_longterm.ek_bytes()
    }

    /// Current PQ rekey generation (see field docs).
    pub fn kyber_generation(&self) -> u64 {
        self.kyber_generation
    }

    /// Retained rekey events newer than `gen`: `(generation, ct)` pairs for
    /// REKEY_REQUEST replays, oldest first.
    pub fn rekey_events_since(&self, gen: u64) -> Vec<(u64, Vec<u8>)> {
        self.retained_rekeys
            .iter()
            .filter(|(g, _, _)| *g > gen)
            .map(|(g, ct, _)| (*g, ct.clone()))
            .collect()
    }

    /// Peer's long-term Kyber ek (our rekey encap target).
    pub fn peer_kyber_ek(&self) -> &[u8] {
        &self.peer_kyber_ek
    }

    pub fn needs_kyber_rekey(&self) -> bool {
        self.secrets.msgs_since_kyber >= KYBER_REKEY_INTERVAL_MSGS
            || self.last_kyber_rekey.elapsed() >= Duration::from_secs(KYBER_REKEY_INTERVAL_SECS)
    }

    /// Periodic Kyber re-encapsulation sub-ratchet (§4.2 steps 1-5).
    /// Encapsulates to the peer's long-term ek stored at handshake time.
    /// Returns the `ct` blob to transmit alongside the next message.
    /// The event is retained (bounded) for REKEY_REQUEST replays.
    pub fn kyber_rekey_initiate(&mut self) -> Result<Vec<u8>> {
        let (ct, k_new) = kyber_encap_to(&self.peer_kyber_ek.clone())?;
        self.mix_kyber_shared(&k_new);
        self.retained_rekeys
            .push_back((self.kyber_generation, ct.clone(), k_new));
        while self.retained_rekeys.len() > RETAINED_REKEYS {
            if let Some((_, _, mut k)) = self.retained_rekeys.pop_front() {
                k.zeroize();
            }
        }
        self.secrets.msgs_since_kyber = 0;
        self.last_kyber_rekey = Instant::now();
        Ok(ct)
    }

    /// Decapsulate a peer rekey with our long-term dk. The long-term pair
    /// is stable: quantum PCS comes from mixing fresh `k_new` into the root,
    /// not from rotating the decap key (whose replacement the peer could
    /// not know without an extra advertisement roundtrip).
    pub fn kyber_rekey_receive(&mut self, ct: &[u8]) -> Result<()> {
        let k_new = self.kyber_longterm.decapsulate(ct)?;
        self.mix_kyber_shared(&k_new);
        self.secrets.msgs_since_kyber = 0;
        self.last_kyber_rekey = Instant::now();
        Ok(())
    }

    fn mix_kyber_shared(&mut self, k_new: &[u8]) {
        let mut ikm = Vec::with_capacity(48 + k_new.len());
        ikm.extend_from_slice(&self.secrets.root_key);
        ikm.extend_from_slice(k_new);
        let okm = hkdf_sha384(&ikm, &[0u8; 48], b"kyber-ratchet", 48);
        self.secrets.root_key.copy_from_slice(&okm);
        self.secrets.kyber_shared = k_new.to_vec();
        self.kyber_generation += 1;
    }

    fn ecdh_shared_or_zero(&self) -> [u8; 32] {
        match self.peer_ecdh_pub {
            Some(pk) => self.ecdh_ratchet.diffie_hellman(&pk),
            None => [0u8; 32],
        }
    }

    fn message_key(&self, counter: u64) -> [u8; 32] {
        let ecdh = self.ecdh_shared_or_zero();
        Self::message_key_raw(
            &self.secrets.root_key,
            &self.secrets.chain_key,
            counter,
            &ecdh,
            &self.secrets.kyber_shared,
        )
    }

    fn message_key_raw(
        root: &[u8; 48],
        chain: &[u8; 48],
        counter: u64,
        ecdh: &[u8; 32],
        kyber_shared: &[u8],
    ) -> [u8; 32] {
        let mut ikm = Vec::new();
        ikm.extend_from_slice(root);
        ikm.extend_from_slice(chain);
        ikm.extend_from_slice(&counter.to_be_bytes());
        ikm.extend_from_slice(ecdh);
        ikm.extend_from_slice(kyber_shared);
        let okm = hkdf_sha384(&ikm, &[0u8; 48], b"Null-v2.0-message-key", 32);
        let mut k = [0u8; 32];
        k.copy_from_slice(&okm);
        k
    }

    fn advance_chain(&mut self) {
        let okm = hkdf_sha384(
            &self.secrets.chain_key,
            &[0u8; 48],
            b"Null-v2.0-chain-step",
            48,
        );
        self.secrets.chain_key.copy_from_slice(&okm);
    }

    fn nonce_for(counter: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&counter.to_be_bytes());
        *Nonce::from_slice(&n)
    }

    /// Encrypt plaintext; advances symmetric + ECDH ratchet every message.
    /// `ad` binds sender/recipient onion + counter + version (§4.2 AD).
    ///
    /// Rotate-before-send: fresh ephemeral is generated FIRST so the DH
    /// contribution `DH(new_secret, peer_pub)` matches what the receiver
    /// computes as `DH(own_secret, new_pub)`. The new pub is sent on-wire.
    /// The current PQ generation rides along for loss detection.
    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<EncryptedMessage> {
        // ECDH ratchet: fresh ephemeral for every message (classical PCS).
        self.ecdh_ratchet = EphemeralKey::generate();
        let counter = self.secrets.send_counter;
        let mut mk = self.message_key(counter);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&mk));
        let nonce = Self::nonce_for(counter);
        let mut buf = plaintext.to_vec();
        cipher
            .encrypt_in_place(&nonce, ad, &mut buf)
            .map_err(|e| NullError::Crypto(format!("aead encrypt: {e}")))?;
        let msg = EncryptedMessage {
            counter,
            kyber_gen: self.kyber_generation,
            ecdh_pub: self.ecdh_ratchet.public_bytes(),
            ciphertext: buf,
        };
        // Symmetric ratchet forward + counters.
        self.advance_chain();
        self.secrets.send_counter += 1;
        self.secrets.msgs_since_kyber += 1;
        mk.zeroize();
        Ok(msg)
    }

    /// Decrypt with out-of-order tolerance (Signal-style skipped keys).
    ///
    /// The chain is pure-symmetric so a late frame's chain key can be served
    /// from the cache filled when jumping over it; the DH contribution is
    /// recomputed from the frame's own ecdh pub. Late frames therefore
    /// decrypt only if we have not rotated our ECDH secret since (i.e. we
    /// have not sent anything after the jump) — documented limitation of
    /// per-message DH rotation.
    ///
    /// PQ generation is checked BEFORE any state mutates: a newer generation
    /// means we lost rekey frames ([`NullError::MissedRekey`], request a
    /// replay and retry later); an older one means the peer is behind
    /// ([`NullError::PeerBehind`], push our retained rekeys to them).
    pub fn decrypt(&mut self, msg: &EncryptedMessage, ad: &[u8]) -> Result<Vec<u8>> {
        if msg.kyber_gen > self.kyber_generation {
            return Err(NullError::MissedRekey {
                have: self.kyber_generation,
                want: msg.kyber_gen,
            });
        }
        if msg.kyber_gen < self.kyber_generation {
            return Err(NullError::PeerBehind {
                have: self.kyber_generation,
                want: msg.kyber_gen,
            });
        }
        // ECDH ratchet: adopt sender's new pub BEFORE deriving the message
        // key, so DH(own_secret, new_pub) == DH(sender_new_secret, own_pub).
        self.peer_ecdh_pub = Some(msg.ecdh_pub);
        let ecdh = self.ecdh_shared_or_zero();
        let chain_for_msg = if msg.counter < self.secrets.recv_counter {
            self.skipped
                .remove(&msg.counter)
                .ok_or_else(|| NullError::Crypto("duplicate or expired message counter".into()))?
        } else {
            if msg.counter - self.secrets.recv_counter > MAX_SKIP {
                return Err(NullError::Crypto("counter gap exceeds skip window".into()));
            }
            while self.secrets.recv_counter < msg.counter {
                if self.skipped.len() >= MAX_SKIP as usize {
                    return Err(NullError::Crypto("skipped-key cache full".into()));
                }
                self.skipped
                    .insert(self.secrets.recv_counter, self.secrets.chain_key);
                self.advance_chain();
                self.secrets.recv_counter += 1;
            }
            let c = self.secrets.chain_key;
            self.advance_chain();
            self.secrets.recv_counter = msg.counter + 1;
            c
        };
        let mut mk = Self::message_key_raw(
            &self.secrets.root_key,
            &chain_for_msg,
            msg.counter,
            &ecdh,
            &self.secrets.kyber_shared,
        );
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&mk));
        let nonce = Self::nonce_for(msg.counter);
        let mut buf = msg.ciphertext.clone();
        cipher
            .decrypt_in_place(&nonce, ad, &mut buf)
            .map_err(|e| NullError::Crypto(format!("aead decrypt: {e}")))?;
        self.secrets.msgs_since_kyber += 1;
        mk.zeroize();
        Ok(buf)
    }

    pub fn send_counter(&self) -> u64 {
        self.secrets.send_counter
    }
}

/// Wire form of one ratchet message (embedded in a 2048B frame).
///
/// Encoding: `counter(8 BE) ‖ kyber_gen(8 BE) ‖ ecdh_pub(32) ‖ ciphertext`.
/// Decoding rejects trailing garbage so frame-padding bugs surface loudly.
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    pub counter: u64,
    pub kyber_gen: u64,
    pub ecdh_pub: [u8; 32],
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48 + self.ciphertext.len());
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&self.kyber_gen.to_be_bytes());
        out.extend_from_slice(&self.ecdh_pub);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 48 {
            return Err(NullError::Crypto(format!(
                "ratchet message too short: {}",
                bytes.len()
            )));
        }
        let counter = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let kyber_gen = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let mut ecdh_pub = [0u8; 32];
        ecdh_pub.copy_from_slice(&bytes[16..48]);
        Ok(Self {
            counter,
            kyber_gen,
            ecdh_pub,
            ciphertext: bytes[48..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_and_message_roundtrip() {
        // Responder pre-generates Kyber keypair; initiator encaps to it.
        let responder_kp = KyberKeypair::generate();
        let (initiator, init) = HandshakeInitiator::initiate(&responder_kp.ek_bytes()).unwrap();
        let (resp, mut sess_b, _k) = respond(&init, &responder_kp).unwrap();
        let mut sess_a = initiator.finalize(&resp).unwrap();
        let ad = b"alice.onion|bob.onion|0|2";
        // A -> B
        let ct = sess_a.encrypt(b"hello null", ad).unwrap();
        let pt = sess_b.decrypt(&ct, ad).unwrap();
        assert_eq!(pt, b"hello null");
        // B -> A (reply uses rotated keys on both sides)
        let ct2 = sess_b.encrypt(b"hello alice", ad).unwrap();
        let pt2 = sess_a.decrypt(&ct2, ad).unwrap();
        assert_eq!(pt2, b"hello alice");
        // A -> B again
        let ct3 = sess_a.encrypt(b"second", ad).unwrap();
        assert_eq!(sess_b.decrypt(&ct3, ad).unwrap(), b"second");
    }

    #[test]
    fn verified_handshake_with_pinning() {
        use crate::identity::IdentityKey;
        let responder_kp = KyberKeypair::generate();
        let id_a = IdentityKey::generate();
        let id_b = IdentityKey::generate();
        let fp_b = id_b.fingerprint();
        // Full verified flow with fingerprint pinning.
        let (initiator, init) =
            HandshakeInitiator::initiate_verified(&responder_kp.ek_bytes(), &id_a).unwrap();
        // Wire roundtrip preserves vk + sig.
        let init2 = HandshakeInit::decode(&init.encode()).unwrap();
        assert!(init2.identity_vk.is_some() && init2.signature.is_some());
        let (resp, mut sess_b, _) = respond_verified(&init2, &responder_kp, &id_b, None).unwrap();
        let resp2 = HandshakeResponse::decode(&resp.encode()).unwrap();
        let mut sess_a = initiator.finalize_verified(&resp2, Some(&fp_b)).unwrap();
        // Wrong pin rejected.
        let (initiator2, init_v2) =
            HandshakeInitiator::initiate_verified(&responder_kp.ek_bytes(), &id_a).unwrap();
        let (resp_v2, _, _) = respond_verified(&init_v2, &responder_kp, &id_b, None).unwrap();
        assert!(initiator2
            .finalize_verified(&resp_v2, Some("ml-dsa:deadbeef"))
            .is_err());
        // Tampered transcript rejected.
        let mut bad = init_v2.clone();
        bad.ephemeral_pub[0] ^= 0xff;
        assert!(respond_verified(&bad, &responder_kp, &id_b, None).is_err());
        // Deniable responder rejects verified finalize (no vk/sig).
        let kp_tmp = KyberKeypair::generate();
        let (i_tmp, m_tmp) = HandshakeInitiator::initiate(&kp_tmp.ek_bytes()).unwrap();
        let (resp_d, _, _) = respond(&m_tmp, &responder_kp).unwrap();
        assert!(i_tmp.finalize_verified(&resp_d, None).is_err());
        // Chat still works on the verified session.
        let ad = b"a|b|2";
        let ct = sess_a.encrypt(b"verified hi", ad).unwrap();
        assert_eq!(sess_b.decrypt(&ct, ad).unwrap(), b"verified hi");
    }

    #[test]
    fn generation_tracks_rekeys_and_gates_decrypt() {
        let responder_kp = KyberKeypair::generate();
        let (initiator, init) = HandshakeInitiator::initiate(&responder_kp.ek_bytes()).unwrap();
        let (resp, mut sess_b, _k) = respond(&init, &responder_kp).unwrap();
        let mut sess_a = initiator.finalize(&resp).unwrap();
        assert_eq!(
            (sess_a.kyber_generation(), sess_b.kyber_generation()),
            (0, 0)
        );
        let ad = b"g";
        // A rekeys alone: its messages now carry gen 1.
        let ct = sess_a.kyber_rekey_initiate().unwrap();
        assert_eq!(sess_a.kyber_generation(), 1);
        assert_eq!(sess_a.rekey_events_since(0).len(), 1);
        assert!(sess_a.rekey_events_since(1).is_empty());
        let m = sess_a.encrypt(b"new epoch", ad).unwrap();
        assert_eq!(m.kyber_gen, 1);
        // B is behind: detectable before any state mutates.
        let err = sess_b.decrypt(&m, ad).unwrap_err();
        assert!(matches!(err, NullError::MissedRekey { have: 0, want: 1 }));
        // B heals from the ct, then decrypts.
        sess_b.kyber_rekey_receive(&ct).unwrap();
        assert_eq!(sess_b.kyber_generation(), 1);
        assert_eq!(sess_b.decrypt(&m, ad).unwrap(), b"new epoch");
        // Stale-generation message against a healed session: peer-behind.
        let mut stale = m.clone();
        stale.kyber_gen = 0;
        let err = sess_b.decrypt(&stale, ad).unwrap_err();
        assert!(matches!(err, NullError::PeerBehind { have: 1, want: 0 }));
    }

    #[test]
    fn kyber_rekey_mixes_root() {
        let root = [7u8; 48];
        let (mut a, mut _b) = Session::new_deterministic_for_test(root);
        let before = a.secrets.root_key;
        // new_from_root points peer_ek at our own ek: self-rekey roundtrips.
        let ct = a.kyber_rekey_initiate().unwrap();
        a.kyber_rekey_receive(&ct).unwrap();
        assert_ne!(before, a.secrets.root_key);
    }

    #[test]
    fn kyber_rekey_between_peers_heals_both_roots() {
        let responder_kp = KyberKeypair::generate();
        let (initiator, init) = HandshakeInitiator::initiate(&responder_kp.ek_bytes()).unwrap();
        let (resp, mut sess_b, _k) = respond(&init, &responder_kp).unwrap();
        let mut sess_a = initiator.finalize(&resp).unwrap();
        let root_a = sess_a.secrets.root_key;
        let root_b = sess_b.secrets.root_key;
        assert_eq!(root_a, root_b);
        // A re-encapsulates to B's long-term ek; B decaps with long-term dk.
        let ct = sess_a.kyber_rekey_initiate().unwrap();
        sess_b.kyber_rekey_receive(&ct).unwrap();
        assert_ne!(sess_a.secrets.root_key, root_a);
        assert_eq!(sess_a.secrets.root_key, sess_b.secrets.root_key);
        assert_eq!(sess_a.secrets.kyber_shared, sess_b.secrets.kyber_shared);
    }

    #[test]
    fn rekey_trigger_at_50() {
        let root = [1u8; 48];
        let (mut a, _b) = Session::new_deterministic_for_test(root);
        assert!(!a.needs_kyber_rekey());
        a.secrets.msgs_since_kyber = 50;
        assert!(a.needs_kyber_rekey());
    }

    #[test]
    fn message_wire_codec_roundtrip() {
        let m = EncryptedMessage {
            counter: 42,
            kyber_gen: 7,
            ecdh_pub: [9u8; 32],
            ciphertext: b"ciphertext-bytes".to_vec(),
        };
        let bytes = m.encode();
        assert_eq!(bytes.len(), 48 + b"ciphertext-bytes".len());
        let back = EncryptedMessage::decode(&bytes).unwrap();
        assert_eq!(back.counter, 42);
        assert_eq!(back.kyber_gen, 7);
        assert_eq!(back.ecdh_pub, [9u8; 32]);
        assert_eq!(back.ciphertext, b"ciphertext-bytes");
        assert!(EncryptedMessage::decode(&bytes[..10]).is_err());
    }

    #[test]
    fn handshake_wire_codec_roundtrip() {
        let responder_kp = KyberKeypair::generate();
        let (_initiator, init) = HandshakeInitiator::initiate(&responder_kp.ek_bytes()).unwrap();
        let back = HandshakeInit::decode(&init.encode()).unwrap();
        assert_eq!(back.ephemeral_pub, init.ephemeral_pub);
        assert_eq!(back.kyber_ct, init.kyber_ct);
        assert_eq!(back.kyber_ek, init.kyber_ek);
        assert!(HandshakeInit::decode(b"short").is_err());
        let (resp, _, _) = respond(&init, &responder_kp).unwrap();
        let back_r = HandshakeResponse::decode(&resp.encode()).unwrap();
        assert_eq!(back_r.ephemeral_pub, resp.ephemeral_pub);
        assert_eq!(back_r.kyber_ek, resp.kyber_ek);
    }

    #[test]
    fn out_of_order_burst_decrypts() {
        let responder_kp = KyberKeypair::generate();
        let (initiator, init) = HandshakeInitiator::initiate(&responder_kp.ek_bytes()).unwrap();
        let (resp, mut sess_b, _k) = respond(&init, &responder_kp).unwrap();
        let mut sess_a = initiator.finalize(&resp).unwrap();
        let ad = b"alice.onion|bob.onion|0|2";
        // A fires a 3-message burst; B stays silent (no ECDH rotation on B).
        let m0 = sess_a.encrypt(b"zero", ad).unwrap();
        let m1 = sess_a.encrypt(b"one", ad).unwrap();
        let m2 = sess_a.encrypt(b"two", ad).unwrap();
        // Deliver 2, 0, 1.
        assert_eq!(sess_b.decrypt(&m2, ad).unwrap(), b"two");
        assert_eq!(sess_b.decrypt(&m0, ad).unwrap(), b"zero");
        assert_eq!(sess_b.decrypt(&m1, ad).unwrap(), b"one");
        // Replay of m0 is now rejected.
        assert!(sess_b.decrypt(&m0, ad).is_err());
    }

    #[test]
    fn counter_gap_bounded() {
        let root = [2u8; 48];
        let (mut a, mut b) = Session::new_deterministic_for_test(root);
        // Align ECDH pubs so decrypt reaches the gap check (aead would fail
        // later anyway, but the gap error must fire first).
        let ad = b"x";
        let mut m = a.encrypt(b"hi", ad).unwrap();
        m.counter = MAX_SKIP + 5;
        assert!(b.decrypt(&m, ad).is_err());
    }
}
