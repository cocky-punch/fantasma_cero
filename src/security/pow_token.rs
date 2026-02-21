use super::helpers;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::Mac;
use rand::RngCore;
use sha2::Digest;
use std::net::IpAddr;
use subtle::ConstantTimeEq;

const NONCE_LEN: usize = 16;
const SIG_LEN: usize = 32;

pub struct PowToken;
impl PowToken {
    pub fn issue(secret: &[u8], ip_addr: &IpAddr, ttl_secs: u64) -> String {
        let expiry = crate::helpers::current_ts() + ttl_secs;

        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);

        let ip_hash = helpers::hash_ip_addr(ip_addr);

        let mut payload = Vec::new();
        payload.extend_from_slice(&expiry.to_be_bytes());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ip_hash);

        let mut mac = helpers::HmacSha256::new_from_slice(secret).unwrap();
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();

        payload.extend_from_slice(&signature);

        URL_SAFE_NO_PAD.encode(payload)
    }

    pub fn verify(secret: &[u8], token: &str, ip_addr: &IpAddr) -> bool {
        let decoded = match URL_SAFE_NO_PAD.decode(token) {
            Ok(v) => v,
            Err(_) => return false,
        };

        if decoded.len() != 8 + NONCE_LEN + 32 + SIG_LEN {
            return false;
        }

        let expiry_bytes = &decoded[0..8];
        let payload_len = 8 + NONCE_LEN + 32;
        let payload = &decoded[0..payload_len];
        let signature = &decoded[payload_len..];

        let expiry = u64::from_be_bytes(expiry_bytes.try_into().unwrap());
        if crate::helpers::current_ts() > expiry {
            return false;
        }

        let ip_hash_expected = helpers::hash_ip_addr(ip_addr);
        if &decoded[8 + NONCE_LEN..payload_len] != ip_hash_expected.as_slice() {
            return false;
        }

        let mut mac = helpers::HmacSha256::new_from_slice(secret).unwrap();
        mac.update(payload);
        let expected_sig = mac.finalize().into_bytes();

        expected_sig.ct_eq(signature).into()
    }

    pub fn issue_cookie(
        secret: &[u8],
        client_ip: &IpAddr,
        cookie_name: &str,
        ttl_secs: u64,
    ) -> String {
        let token = Self::issue(secret, client_ip, ttl_secs);
        format!(
            "{cookie_name}={token}; Path=/; Max-Age={ttl_secs}; HttpOnly; Secure; SameSite=Strict"
        )
    }
}
