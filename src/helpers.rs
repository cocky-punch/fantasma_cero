use axum::body::Body;
use axum::http::Request;
use std::net::IpAddr;

pub fn get_challenge_bootstrap_html() -> String {
    r#"
<!DOCTYPE html>
<html>
<head><title>Verifying...</title></head>
<body>
<script>
    (async function () {
        const res = await fetch('/challenge');
        const challenge = await res.json();


        //TODO
        // replace with actual one
        const solution = solvePow(challenge); // implement this on frontend


        const resp = await fetch('/solve', {
            method: 'POST',
            body: JSON.stringify(solution),
            headers: { 'Content-Type': 'application/json' }
        });

        if (resp.ok) {
            location.reload();
        }
    })();
</script>
</body>
</html>
"#
    .to_string()
}

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
        if let Some(version) = ua[pos+7..].split('.').next() {
            parts.push(format!("Chrome/{}", version));
        }
    } else if let Some(pos) = ua_lower.find("firefox/") {
        if let Some(version) = ua[pos+8..].split('.').next() {
            parts.push(format!("Firefox/{}", version));
        }
    } else if let Some(pos) = ua_lower.find("safari/") {
        // Safari version detection is tricky, use "Version/" instead
        if let Some(ver_pos) = ua_lower.find("version/") {
            if let Some(version) = ua[ver_pos+8..].split('.').next() {
                parts.push(format!("Safari/{}", version));
            }
        } else {
            parts.push("Safari".to_string());
        }
    } else if ua_lower.contains("edge/") {
        if let Some(pos) = ua_lower.find("edge/") {
            if let Some(version) = ua[pos+5..].split('.').next() {
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
