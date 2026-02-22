use axum::body::Body;
use axum::http::HeaderMap;
use axum::http::Request;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config;

pub fn get_client_ip(req: &Request<Body>) -> Option<IpAddr> {
    // Try X-Forwarded-For header (may contain multiple IPs)
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(first_ip) = xff_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }

    // Try Forwarded header (e.g., Forwarded: for=1.2.3.4)
    if let Some(fwd) = req.headers().get("forwarded") {
        if let Ok(fwd_str) = fwd.to_str() {
            for part in fwd_str.split(';') {
                if let Some(ip_str) = part.strip_prefix("for=") {
                    if let Ok(ip) = ip_str.trim().parse() {
                        return Some(ip);
                    }
                }
            }
        }
    }

    // Fallback: use remote address if available
    if let Some(addr) = req.extensions().get::<std::net::SocketAddr>() {
        return Some(addr.ip());
    }

    None
}

pub fn is_hop_by_hop_http_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "host"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

pub fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    let to_remove: Vec<axum::http::HeaderName> = headers
        .keys()
        .filter(|name| is_hop_by_hop_http_header(name.as_str()))
        .cloned()
        .collect();

    for name in to_remove {
        headers.remove(name);
    }
}

pub fn normalize_user_agent(ua: &str) -> String {
    // Extract key identifiers, ignore minor versions
    //
    // this:
    // "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    //
    // will →
    // "Chrome/120 Windows"

    let ua_lower = ua.to_lowercase();
    let mut parts = Vec::new();

    // Browser detection (major version only)
    if let Some(pos) = ua_lower.find("chrome/") {
        if let Some(version) = ua[pos + 7..].split('.').next() {
            parts.push(format!("Chrome/{}", version));
        }
    } else if let Some(pos) = ua_lower.find("firefox/") {
        if let Some(version) = ua[pos + 8..].split('.').next() {
            parts.push(format!("Firefox/{}", version));
        }
    } else if let Some(pos) = ua_lower.find("safari/") {
        // Safari version detection is tricky, use "Version/" instead
        if let Some(ver_pos) = ua_lower.find("version/") {
            if let Some(version) = ua[ver_pos + 8..].split('.').next() {
                parts.push(format!("Safari/{}", version));
            }
        } else {
            parts.push("Safari".to_string());
        }
    } else if ua_lower.contains("edge/") {
        if let Some(pos) = ua_lower.find("edge/") {
            if let Some(version) = ua[pos + 5..].split('.').next() {
                parts.push(format!("Edge/{}", version));
            }
        }
    }

    // OS detection
    if ua_lower.contains("windows nt 10") {
        parts.push("Windows10".to_string());
    } else if ua_lower.contains("windows nt 11") {
        parts.push("Windows11".to_string());
    } else if ua_lower.contains("mac os x") {
        parts.push("MacOS".to_string());
    } else if ua_lower.contains("linux") {
        parts.push("Linux".to_string());
    } else if ua_lower.contains("android") {
        parts.push("Android".to_string());
    } else if ua_lower.contains("iphone") || ua_lower.contains("ipad") {
        parts.push("iOS".to_string());
    }

    // Architecture
    if ua_lower.contains("x64") || ua_lower.contains("x86_64") {
        parts.push("x64".to_string());
    } else if ua_lower.contains("arm") {
        parts.push("ARM".to_string());
    }

    if parts.is_empty() {
        // Fallback: use first 50 chars of UA
        ua[..std::cmp::min(50, ua.len())].to_string()
    } else {
        parts.join("_")
    }
}

fn compare_browser_fingerprints(stored: &str, current: &str) -> u32 {
    let stored_fp: Result<Value, _> = serde_json::from_str(stored);
    let current_fp: Result<Value, _> = serde_json::from_str(current);

    if stored_fp.is_err() || current_fp.is_err() {
        return 0;
    }

    let stored = stored_fp.unwrap();
    let current = current_fp.unwrap();

    let mut suspicion = 0;

    // Canvas fingerprint - very stable
    if stored.get("canvas") != current.get("canvas") {
        suspicion += 30;
    }

    // WebGL fingerprint - hardware-specific
    if stored.get("webgl") != current.get("webgl") {
        suspicion += 30;
    }

    // Platform - OS shouldn't change often
    if stored.get("platform") != current.get("platform") {
        suspicion += 25;
    }

    // Screen resolution
    if let (Some(stored_screen), Some(current_screen)) =
        (stored.get("screen"), current.get("screen"))
    {
        if stored_screen.get("width") != current_screen.get("width")
            || stored_screen.get("height") != current_screen.get("height")
        {
            suspicion += 10;
        }
        if stored_screen.get("colorDepth") != current_screen.get("colorDepth") {
            suspicion += 15;
        }
    }

    // Hardware concurrency
    if stored.get("hardwareConcurrency") != current.get("hardwareConcurrency") {
        suspicion += 15;
    }

    // Fonts
    if stored.get("fonts") != current.get("fonts") {
        suspicion += 8;
    }

    suspicion
}

fn get_tls_fingerprint(headers: &HeaderMap) -> String {
    let mut parts = Vec::new();

    // Normalized User-Agent
    if let Some(ua) = headers.get("user-agent") {
        if let Ok(s) = ua.to_str() {
            parts.push(format!("ua:{}", normalize_user_agent(s)));
        }
    }

    // Accept-Encoding (stable)
    if let Some(enc) = headers.get("accept-encoding") {
        if let Ok(s) = enc.to_str() {
            let mut encodings: Vec<&str> = s
                .split(',')
                .map(|e| e.trim())
                .filter(|e| !e.is_empty())
                .collect();
            encodings.sort();
            parts.push(format!("enc:{}", encodings.join(",")));
        }
    }

    // Accept-Language (primary only)
    if let Some(lang) = headers.get("accept-language") {
        if let Ok(s) = lang.to_str() {
            let primary = s
                .split(',')
                .next()
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            if !primary.is_empty() {
                parts.push(format!("lang:{}", primary));
            }
        }
    }

    // Client Hints (Chromium)
    if let Some(ch_ua) = headers.get("sec-ch-ua") {
        if let Ok(s) = ch_ua.to_str() {
            parts.push(format!("ch-ua:{}", s));
        }
    }
    if let Some(ch_platform) = headers.get("sec-ch-ua-platform") {
        if let Ok(s) = ch_platform.to_str() {
            parts.push(format!("ch-platform:{}", s));
        }
    }

    if parts.is_empty() {
        return String::new();
    }

    let combined = parts.join("|");
    let hash = Sha256::digest(combined.as_bytes());
    hex::encode(hash)[..16].to_string()
}

pub fn current_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub async fn init_db() -> sqlx::SqlitePool {
    let db_conn_str = format!("sqlite:{}", config::CONFIG.persistence.sqlite_path);
    let pool = sqlx::SqlitePool::connect(&db_conn_str).await.unwrap();

    sqlx::query("PRAGMA journal_mode=WAL;")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("PRAGMA synchronous=NORMAL;")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("PRAGMA temp_store=MEMORY;")
        .execute(&pool)
        .await
        .unwrap();

    pool
}
