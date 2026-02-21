use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

pub type HmacSha256 = Hmac<Sha256>;

pub fn hash_ip_addr(ip_addr: &IpAddr) -> [u8; 32] {
    match ip_addr {
        IpAddr::V4(v4) => Sha256::digest(v4.octets()).into(),
        IpAddr::V6(v6) => Sha256::digest(v6.octets()).into(),
    }
}

pub fn sign(secret: &[u8], payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn ua_hash(ua: &str) -> String {
    let mut h = Sha256::new();
    h.update(ua.as_bytes());
    hex::encode(h.finalize())
}

pub fn ip_prefix(ip_addr: &IpAddr) -> String {
    match ip_addr {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        std::net::IpAddr::V6(v6) => {
            let seg = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", seg[0], seg[1], seg[2], seg[3])
        }
    }
}
