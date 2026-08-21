//! ShadowScan — lightweight web vulnerability scanner.
//!
//! Performs four checks against a target:
//!   1. Security header audit (HSTS, CSP, XFO, nosniff, ...)
//!   2. TLS / certificate inspection (for https targets)
//!   3. Reflected SQLi & XSS probes (error/reflection heuristics)
//!   4. Common path discovery (HTTP status based)

use std::env;
use std::time::Duration;

use ureq::{Agent, AgentBuilder};

const VERSION: &str = "1.0.0";

// Security headers worth checking.
const SECURITY_HEADERS: &[(&str, &str)] = &[
    (
        "strict-transport-security",
        "Missing HSTS (HTTP Strict Transport Security)",
    ),
    (
        "content-security-policy",
        "Missing CSP (Content-Security-Policy)",
    ),
    (
        "x-frame-options",
        "Missing X-Frame-Options (clickjacking protection)",
    ),
    (
        "x-content-type-options",
        "Missing X-Content-Type-Options: nosniff",
    ),
    ("referrer-policy", "Missing Referrer-Policy"),
    ("permissions-policy", "Missing Permissions-Policy"),
    (
        "cross-origin-opener-policy",
        "Missing COOP (Cross-Origin-Opener-Policy)",
    ),
    ("x-xss-protection", "Missing X-XSS-Protection"),
];

// Payloads used for reflection detection.
const SQLI_PAYLOADS: &[&str] = &[
    "' OR '1'='1",
    "\" OR 1=1 --",
    "' UNION SELECT NULL--",
    "'; DROP TABLE x--",
    "1' AND '1'='1",
];

const XSS_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "';alert(1);//",
];

// Paths probed during discovery.
const COMMON_PATHS: &[&str] = &[
    "/robots.txt",
    "/sitemap.xml",
    "/.git/config",
    "/.env",
    "/.gitignore",
    "/admin",
    "/api",
    "/api/health",
    "/api/v1",
    "/swagger",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/graphql",
    "/config",
    "/backup",
    "/wp-admin",
    "/wp-login.php",
    "/server-status",
    "/actuator",
    "/actuator/health",
    "/login",
    "/register",
    "/uploads/",
    "/phpinfo.php",
    "/debug",
    "/console",
    "/trace",
    "/metrics",
    "/health",
    "/version",
];

fn normalize_target(raw: &str) -> String {
    let mut t = raw.trim().to_string();
    if !t.starts_with("http://") && !t.starts_with("https://") {
        t = format!("http://{t}");
    }
    while t.ends_with('/') {
        t.pop();
    }
    t
}

fn check_headers(agent: &Agent, base: &str, findings: &mut Vec<String>) {
    match agent.get(base).call() {
        Ok(resp) => {
            let headers = resp.headers_names();
            let mut found = 0usize;
            for (hdr, msg) in SECURITY_HEADERS {
                if headers.iter().any(|h| h.eq_ignore_ascii_case(hdr)) {
                    found += 1;
                } else {
                    findings.push(format!("[header] {msg}"));
                }
            }
            let server = resp.header("server").unwrap_or("?");
            let powered = resp.header("x-powered-by").unwrap_or("none");
            findings.push(format!(
                "[header] server={server}, x-powered-by={powered} (present {found}/{} security headers)",
                SECURITY_HEADERS.len()
            ));
        }
        Err(ureq::Error::Status(code, _)) => {
            findings.push(format!("[header] HTTP {code} on GET {base}"));
        }
        Err(e) => {
            findings.push(format!("[header] request failed: {e}"));
        }
    }
}

fn check_tls(base: &str, findings: &mut Vec<String>) {
    if !base.starts_with("https://") {
        return;
    }
    let hostport = base
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("");
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
            (h, p.parse::<u16>().unwrap_or(443))
        }
        _ => (hostport, 443),
    };
    let builder = match openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()) {
        Ok(b) => b,
        Err(e) => {
            findings.push(format!("[tls] connector error: {e}"));
            return;
        }
    };
    let mut builder = builder;
    builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let connector = builder.build();
    let addr = format!("{host}:{port}");
    if let Ok(stream) = std::net::TcpStream::connect(&addr) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        if let Ok(tls) = connector.connect(host, stream) {
            if let Some(peer_cert) = tls.ssl().peer_certificate() {
                let subject = peer_cert.subject_name();
                let issuer = peer_cert.issuer_name();
                let not_after = peer_cert.not_after();
                let s = format!("{:?}", subject);
                let i = format!("{:?}", issuer);
                findings.push(format!("[tls] subject={s} issuer={i} expires={not_after}"));
            }
            let version = tls.ssl().version_str();
            let cipher = tls.ssl().current_cipher().map(|c| c.name()).unwrap_or("?");
            findings.push(format!("[tls] negotiated={version} cipher={cipher}"));
            return;
        }
    }
    findings.push("[tls] handshake failed".into());
}

fn reflect_probe(
    agent: &Agent,
    base: &str,
    param: &str,
    payload: &str,
    url_enc: bool,
) -> Option<String> {
    let encoded = if url_enc {
        payload
            .replace(' ', "%20")
            .replace('<', "%3C")
            .replace('>', "%3E")
            .replace('"', "%22")
            .replace('\'', "%27")
    } else {
        payload.to_string()
    };
    let url = format!("{base}/?{param}={encoded}");
    match agent.get(&url).call() {
        Ok(resp) => {
            let body = resp.into_string().unwrap_or_default();
            if body.contains(payload) {
                return Some(url);
            }
            None
        }
        Err(_) => None,
    }
}

fn check_injection(agent: &Agent, base: &str, findings: &mut Vec<String>) {
    // Reflected XSS probes.
    let mut xss_hits = 0;
    for payload in XSS_PAYLOADS {
        if let Some(url) = reflect_probe(agent, base, "q", payload, true) {
            xss_hits += 1;
            findings.push(format!("[xss] potential reflected XSS: {url}"));
            break;
        }
    }
    if xss_hits == 0 {
        findings.push("[xss] no obvious reflected XSS on /?q=".into());
    }

    // SQLi probes: look for SQL error signatures in the response.
    let error_patterns = [
        "SQL syntax",
        "mysql_fetch",
        "You have an error in your SQL syntax",
        "Unclosed quotation mark",
        "ORA-",
        "PostgreSQL",
        "SQLite",
        "syntax error",
        "Microsoft OLE DB",
        "ODBC SQL Server Driver",
        "unknown column",
        "Warning: mysql_",
        "Division by zero",
    ];
    let mut sqli_hits = 0;
    for payload in SQLI_PAYLOADS {
        let url = format!("{base}/?id={}", payload.replace(' ', "%20"));
        if let Ok(resp) = agent.get(&url).call() {
            let body = resp.into_string().unwrap_or_default();
            if error_patterns.iter().any(|p| body.contains(p)) {
                sqli_hits += 1;
                findings.push(format!("[sqli] possible SQLi (error signature): {url}"));
                break;
            }
        }
    }
    if sqli_hits == 0 {
        findings.push("[sqli] no error-based SQLi signature on /?id=".into());
    }
}

fn path_discovery(agent: &Agent, base: &str, findings: &mut Vec<String>) {
    let mut hits = 0;
    for path in COMMON_PATHS {
        let url = format!("{base}{path}");
        match agent.get(&url).call() {
            Ok(resp) => {
                let status = resp.status();
                let size = resp
                    .header("content-length")
                    .map(|v| v.to_string().to_string())
                    .unwrap_or_else(|| resp.into_string().unwrap_or_default().len().to_string());
                findings.push(format!("[path] {status} {path} (size {size})"));
                hits += 1;
            }
            Err(ureq::Error::Status(status, _)) => {
                if status == 401 || status == 403 || status == 500 {
                    findings.push(format!("[path] {status} {path} (exists, protected)"));
                    hits += 1;
                }
            }
            Err(_) => {}
        }
    }
    if hits == 0 {
        findings.push("[path] no interesting paths found".into());
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        println!(
            "ShadowScan {VERSION} — web vulnerability scanner\n\
             \n\
             USAGE: shadowscan <url> [--timeout SECS]\n\
             \n\
             Checks: security headers, TLS config, reflected XSS / SQLi probes,\n\
             common path discovery.\n\
             \n\
             EXAMPLES:\n  shadowscan https://example.com\n  shadowscan http://192.168.1.10:8080 --timeout 5"
        );
        return;
    }

    let mut target = String::new();
    let mut timeout = 10u64;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--timeout" => {
                i += 1;
                timeout = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(10);
            }
            other if target.is_empty() => target = other.to_string(),
            _ => {}
        }
        i += 1;
    }

    let base = normalize_target(&target);
    println!("[*] ShadowScan {VERSION} | target: {base}");
    println!("[*] timeout: {timeout}s\n");

    let agent: Agent = AgentBuilder::new()
        .timeout(Duration::from_secs(timeout))
        .user_agent(&format!("ShadowScan/{VERSION}"))
        .build();

    let mut findings: Vec<String> = Vec::new();

    println!("[1/4] security headers");
    check_headers(&agent, &base, &mut findings);
    println!("[2/4] TLS inspection");
    check_tls(&base, &mut findings);
    println!("[3/4] injection probes (XSS / SQLi)");
    check_injection(&agent, &base, &mut findings);
    println!("[4/4] path discovery");
    path_discovery(&agent, &base, &mut findings);

    println!("\n=== findings ===");
    for f in &findings {
        println!("  {f}");
    }
    println!("\n[*] done: {} findings", findings.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_target_adds_scheme_and_strips_slash() {
        assert_eq!(normalize_target("example.com"), "http://example.com");
        assert_eq!(normalize_target("  example.com/  "), "http://example.com");
        assert_eq!(
            normalize_target("https://example.com"),
            "https://example.com"
        );
        assert_eq!(
            normalize_target("https://example.com///"),
            "https://example.com"
        );
    }

    #[test]
    fn normalize_target_keeps_paths() {
        assert_eq!(
            normalize_target("https://example.com/admin"),
            "https://example.com/admin"
        );
    }

    #[test]
    fn normalize_target_keeps_ports_and_queries() {
        assert_eq!(
            normalize_target("example.com:8080/path?q=1&r=2"),
            "http://example.com:8080/path?q=1&r=2"
        );
        assert_eq!(
            normalize_target("https://example.com:8443/"),
            "https://example.com:8443"
        );
    }

    #[test]
    fn normalize_target_trims_whitespace_and_slashes() {
        assert_eq!(normalize_target("  example.com///  "), "http://example.com");
        assert_eq!(
            normalize_target("http://example.com////"),
            "http://example.com"
        );
    }

    #[test]
    fn normalize_target_preserves_explicit_schemes() {
        assert_eq!(
            normalize_target("https://secure.example"),
            "https://secure.example"
        );
        // Only lowercase schemes are recognised — uppercase is treated as a
        // bare host and gets a scheme prepended.
        assert_eq!(
            normalize_target("HTTP://upper.example"),
            "http://HTTP://upper.example"
        );
    }
}
