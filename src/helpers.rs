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
