use crate::consts::server_ecdh;
use crate::{MmtlsError, Result, TrafficKeyPair};
use hmac::Mac;
use p256::ecdsa::signature::Verifier;
use p256::elliptic_curve::{Generate, ecdh::diffie_hellman};
use p256::{PublicKey, SecretKey};
use sha2::Digest;

pub fn generate_key_pairs() -> Result<(SecretKey, SecretKey)> {
    let pub_key = SecretKey::generate();
    let verify = SecretKey::generate();
    Ok((pub_key, verify))
}

pub fn compute_ephemeral_secret(their_pk: &PublicKey, our_sk: &SecretKey) -> Vec<u8> {
    let shared = diffie_hellman(our_sk.to_nonzero_scalar(), their_pk.as_affine());
    let raw = shared.raw_secret_bytes();
    sha2::Sha256::digest(raw).to_vec()
}

pub fn compute_traffic_key_n(share_key: &[u8], info: &[u8], n: usize) -> Result<TrafficKeyPair> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::from_prk(share_key)
        .map_err(|_| MmtlsError::Crypto("invalid prk for traffic key".into()))?;
    let mut okm = vec![0u8; n];
    hk.expand(info, &mut okm)
        .map_err(|_| MmtlsError::Crypto("hkdf expand failed".into()))?;

    let mut pair = TrafficKeyPair {
        client_key: Vec::new(),
        server_key: Vec::new(),
        client_nonce: Vec::new(),
        server_nonce: Vec::new(),
    };

    if n == 56 {
        pair.client_key = okm[0..16].to_vec();
        pair.server_key = okm[16..32].to_vec();
        pair.client_nonce = okm[32..44].to_vec();
        pair.server_nonce = okm[44..56].to_vec();
    } else if n == 28 {
        pair.client_key = okm[0..16].to_vec();
        pair.client_nonce = okm[16..28].to_vec();
    }

    Ok(pair)
}

pub fn verify_ecdsa_signature(handshake_hash: &[u8], data: &[u8]) -> bool {
    use p256::ecdsa::{Signature, VerifyingKey};

    let data_hash = sha2::Sha256::digest(handshake_hash);

    let sig = match Signature::from_der(data) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let vk = VerifyingKey::from(*server_ecdh());
    vk.verify(&data_hash, &sig).is_ok()
}

pub fn build_hkdf_info(prefix: &str, handshake_hasher: Option<&sha2::Sha256>) -> Vec<u8> {
    let mut info = prefix.as_bytes().to_vec();
    if let Some(hasher) = handshake_hasher {
        let hash = hasher.clone().finalize();
        info.extend_from_slice(&hash);
    }
    info
}

pub fn compute_hmac(k: &[u8], d: &[u8]) -> Vec<u8> {
    use hmac::KeyInit;
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(k).expect("HMAC can take key of any size");
    mac.update(d);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{PublicKey, SecretKey};

    #[test]
    fn test_ecdh_against_go() {
        // Values from a successful Go handshake (Test1RTTECDHEHandshake)
        let x_hex = "2af8c543272c2e4bbde99edea83f15ff825347f5930413f152dc3315b8ba5206";
        let y_hex = "fa95d9f479207de4cee9fff4706bec3d7ce776a726ac580f2f0108a31459cd19";
        let d_hex = "63ae700d9b7429a096e6547a5c6460cfa537db2ab4f6126c410bfa2e5637cf37";
        let expected_hex = "f17aea4c5ed527fc5d9963ae1fe3bf809b577eb7355d41914a4715db746d9f89";

        let mut sec1 = vec![0x04u8];
        sec1.extend_from_slice(&hex::decode(x_hex).unwrap());
        sec1.extend_from_slice(&hex::decode(y_hex).unwrap());
        let their_pk = PublicKey::from_sec1_bytes(&sec1).unwrap();

        let d_bytes: [u8; 32] = hex::decode(d_hex).unwrap().try_into().unwrap();
        let our_sk = SecretKey::from_bytes(&d_bytes.into()).unwrap();

        let comkey = compute_ephemeral_secret(&their_pk, &our_sk);
        assert_eq!(hex::encode(&comkey), expected_hex);
    }
}
