use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use std::net::IpAddr;
use subtle::ConstantTimeEq;

use super::helpers;

pub struct JsToken;
impl JsToken {
    pub fn issue(secret: &[u8], ip_addr: &IpAddr, user_agent: &str) -> String {
        let ts = crate::helpers::current_ts();
        let ip_pfx = helpers::ip_prefix(ip_addr);
        let ua_h = helpers::ua_hash(user_agent);
        let payload = format!("{ts}|{ip_pfx}|{ua_h}");
        let sig = helpers::sign(secret, &payload);
        let token = format!("{payload}|{sig}");

        URL_SAFE_NO_PAD.encode(token)
    }

    pub fn verify(
        secret: &[u8],
        token: &str,
        client_ip: &IpAddr,
        user_agent: &str,
        max_age_secs: u64,
    ) -> bool {
        let decoded = match URL_SAFE_NO_PAD.decode(token) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let s = match String::from_utf8(decoded) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let parts: Vec<&str> = s.split('|').collect();
        if parts.len() != 4 {
            return false;
        }

        let ts: u64 = match parts[0].parse() {
            Ok(v) => v,
            Err(_) => return false,
        };

        if crate::helpers::current_ts().saturating_sub(ts) > max_age_secs {
            return false;
        }

        let expected_ip = helpers::ip_prefix(client_ip);
        let expected_ua = helpers::ua_hash(user_agent);

        if parts[1] != expected_ip || parts[2] != expected_ua {
            return false;
        }

        let payload = format!("{}|{}|{}", parts[0], parts[1], parts[2]);
        let expected_sig = helpers::sign(secret, &payload);

        expected_sig.as_bytes().ct_eq(parts[3].as_bytes()).into()
    }

    pub fn issue_cookie(
        secret: &[u8],
        ip_addr: &IpAddr,
        user_agent: &str,
        cookie_name: &str,
        max_age_secs: u64,
    ) -> String {
        let token = Self::issue(secret, ip_addr, user_agent);
        format!("{cookie_name}={token}; Path=/; Max-Age={max_age_secs}; HttpOnly; SameSite=Lax")
    }
}
