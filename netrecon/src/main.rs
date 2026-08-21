//! NetRecon — concurrent TCP port scanner with banner grabbing.
//!
//! Uses a fixed worker pool with atomic work-stealing. Each probe performs a
//! timed connect + optional banner read. Results are printed as they are
//! found and (optionally) dumped as JSON.

use std::env;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const VERSION: &str = "1.0.0";
const DEFAULT_TIMEOUT_MS: u64 = 1_000;
const DEFAULT_THREADS: usize = 128;
const BANNER_READ_MS: u64 = 1_500;

/// Port -> most common service name (IANA + well-known).
fn service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67 | 68 => "dhcp",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        161 | 162 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        514 => "syslog",
        587 => "smtp-submission",
        636 => "ldaps",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "mssql",
        1521 => "oracle",
        2049 => "nfs",
        2181 => "zookeeper",
        2375 | 2376 => "docker",
        3000 => "gitea/grafana",
        3128 => "squid",
        3306 => "mysql",
        3389 => "rdp",
        4369 => "epmd",
        5000 => "upnp",
        5432 => "postgresql",
        5900 => "vnc",
        5984 => "couchdb",
        6379 => "redis",
        6443 => "kubernetes",
        7001 => "weblogic",
        8000 => "http-alt",
        8008 => "http-alt",
        8080 => "http-proxy",
        8081 => "http-alt",
        8443 => "https-alt",
        8888 => "http-alt",
        9000 => "php-fpm",
        9092 => "kafka",
        9200 | 9300 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        50000 => "sap",
        _ => "unknown",
    }
}

/// A single discovered open port.
#[derive(Debug, Clone)]
struct Found {
    addr: IpAddr,
    port: u16,
    service: &'static str,
    banner: Option<String>,
}

fn parse_cidr(s: &str) -> Result<Vec<IpAddr>, String> {
    let (ip_str, prefix_str) = match s.split_once('/') {
        Some(p) => p,
        None => {
            // Single host: try IP first, then hostname resolution.
            if let Ok(ip) = s.parse::<IpAddr>() {
                return Ok(vec![ip]);
            }
            let resolved: Vec<IpAddr> = (s, 0)
                .to_socket_addrs()
                .map_err(|_| format!("cannot resolve host: {s}"))?
                .map(|sa| sa.ip())
                .collect();
            if resolved.is_empty() {
                return Err(format!("cannot resolve host: {s}"));
            }
            return Ok(resolved);
        }
    };
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| format!("invalid IP: {ip_str}"))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| format!("invalid prefix: {prefix_str}"))?;
    if prefix > 32 {
        return Err("prefix must be <= 32".into());
    }
    let base = match ip {
        IpAddr::V4(v4) => u32::from(v4),
        IpAddr::V6(_) => return Err("IPv6 CIDR not supported yet".into()),
    };
    if prefix < 8 {
        return Err(format!(
            "refusing /{prefix}: scanning more than 16M hosts is impractical"
        ));
    }
    let host_bits = 32 - prefix;
    let count = 1u32 << host_bits;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << host_bits
    };
    let network = base & mask;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let addr = network | i;
        out.push(IpAddr::V4(addr.into()));
    }
    Ok(out)
}

fn expand_targets(args: &[String]) -> Result<Vec<(IpAddr, u16)>, String> {
    let host_arg = args
        .first()
        .ok_or("usage: netrecon <target> [ports] [options]")?;
    let port_arg = args.get(1).map(|s| s.as_str()).unwrap_or("1-1024");
    let addrs = parse_cidr(host_arg)?;
    let ports = parse_ports(port_arg)?;
    let mut out = Vec::new();
    for a in &addrs {
        for p in &ports {
            out.push((*a, *p));
        }
    }
    Ok(out)
}

fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: u16 = lo.parse().map_err(|_| format!("bad port range: {part}"))?;
            let hi: u16 = hi.parse().map_err(|_| format!("bad port range: {part}"))?;
            if lo > hi {
                return Err(format!("bad port range: {part}"));
            }
            for p in lo..=hi {
                ports.push(p);
            }
        } else {
            ports.push(part.parse().map_err(|_| format!("bad port: {part}"))?);
        }
    }
    if ports.is_empty() {
        return Err("no ports specified".into());
    }
    Ok(ports)
}

fn probe(addr: IpAddr, port: u16, timeout: Duration) -> Option<Found> {
    let sock_addr = SocketAddr::new(addr, port);
    let stream = match TcpStream::connect_timeout(&sock_addr, timeout) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let service = service_name(port);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(BANNER_READ_MS)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));

    // Best-effort banner grab: send a generic probe then read what comes back.
    let mut banner: Option<String> = None;
    let mut sock = stream;
    let mut buf = [0u8; 512];
    // Some services respond to a bare CRLF (HTTP, SMTP, FTP, SSH...).
    let _ = sock.write_all(b"\r\n");
    match sock.read(&mut buf) {
        Ok(n) if n > 0 => {
            let text = String::from_utf8_lossy(&buf[..n.min(200)])
                .trim()
                .to_string();
            if !text.is_empty() {
                banner = Some(text);
            }
        }
        _ => {}
    }
    Some(Found {
        addr,
        port,
        service,
        banner,
    })
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        println!(
            "NetRecon {VERSION} — concurrent TCP port scanner with banner grabbing\n\
             \n\
             USAGE:\n  netrecon <target> [ports] [--threads N] [--timeout MS] [--json]\n\
             \n\
             ARGUMENTS:\n  target   IP address, hostname, or CIDR (e.g. 10.0.0.0/24)\n  ports    comma list and/or ranges (default 1-1024)\n\
             \n\
             OPTIONS:\n  --threads N   worker threads (default {DEFAULT_THREADS})\n  --timeout MS  connect timeout ms (default {DEFAULT_TIMEOUT_MS})\n  --json        JSON-lines output"
        );
        return;
    }

    let mut json_out = false;
    let mut threads = DEFAULT_THREADS;
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut pos_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json_out = true,
            "--threads" => {
                i += 1;
                threads = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(DEFAULT_THREADS);
            }
            "--timeout" => {
                i += 1;
                timeout_ms = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(DEFAULT_TIMEOUT_MS);
            }
            other => pos_args.push(other.to_string()),
        }
        i += 1;
    }

    let targets = match expand_targets(&pos_args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    let threads = threads.clamp(1, 4096);
    let timeout = Duration::from_millis(timeout_ms);
    println!(
        "[*] NetRecon {} | {} probes | {} workers | timeout {}ms",
        VERSION,
        targets.len(),
        threads,
        timeout_ms
    );

    let queue: Arc<Mutex<std::collections::VecDeque<(IpAddr, u16)>>> =
        Arc::new(Mutex::new(targets.into_iter().collect()));
    let counter = Arc::new(AtomicUsize::new(0));
    let results: Arc<Mutex<Vec<Found>>> = Arc::new(Mutex::new(Vec::new()));
    let total = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..threads {
        let queue = queue.clone();
        let counter = counter.clone();
        let results = results.clone();
        let total = total.clone();
        handles.push(thread::spawn(move || loop {
            let next = {
                let mut q = queue.lock().unwrap();
                q.pop_front()
            };
            let (addr, port) = match next {
                Some(x) => x,
                None => break,
            };
            counter.fetch_add(1, Ordering::Relaxed);
            if let Some(found) = probe(addr, port, timeout) {
                total.fetch_add(1, Ordering::Relaxed);
                results.lock().unwrap().push(found);
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }

    let mut found: Vec<Found> = results.lock().unwrap().clone();
    found.sort_by_key(|f| (f.addr, f.port));

    if json_out {
        for f in &found {
            println!(
                "{{\"addr\":\"{}\",\"port\":{},\"service\":\"{}\",\"banner\":{}}}",
                f.addr,
                f.port,
                f.service,
                match &f.banner {
                    Some(b) => format!("\"{}\"", b.replace('"', "\\\"")),
                    None => "null".to_string(),
                }
            );
        }
    } else {
        for f in &found {
            println!(
                "{:>15}:{:<6} {:<16} {}",
                f.addr,
                f.port,
                f.service,
                f.banner.as_deref().unwrap_or("")
            );
        }
    }
    println!(
        "[*] done: {} probes, {} open",
        counter.load(Ordering::Relaxed),
        found.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_names_are_known() {
        assert_eq!(service_name(22), "ssh");
        assert_eq!(service_name(80), "http");
        assert_eq!(service_name(443), "https");
        assert_eq!(service_name(3306), "mysql");
        assert_eq!(service_name(5432), "postgresql");
        assert_eq!(service_name(65_000), "unknown");
    }

    #[test]
    fn parse_ports_handles_ranges_and_whitespace() {
        assert_eq!(parse_ports("22,80, 443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("22-24").unwrap(), vec![22, 23, 24]);
        assert!(parse_ports("70000").is_err());
    }

    #[test]
    fn parse_cidr_expands_subnets() {
        let addrs = parse_cidr("10.0.0.0/30").unwrap();
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs[0].to_string(), "10.0.0.0");
        assert_eq!(addrs[3].to_string(), "10.0.0.3");
    }

    #[test]
    fn parse_cidr_accepts_single_ip() {
        let addrs = parse_cidr("127.0.0.1").unwrap();
        assert_eq!(addrs, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert!(parse_cidr("999.1.1.1").is_err());
    }

    #[test]
    fn parse_ports_rejects_invalid_forms() {
        assert!(parse_ports("").is_err(), "empty input must fail");
        assert!(parse_ports(",,").is_err(), "only separators must fail");
        assert!(parse_ports("80-79").is_err(), "lo > hi range must fail");
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("70000").is_err(), "out-of-range port must fail");
    }

    #[test]
    fn parse_ports_keeps_overlapping_entries_in_order() {
        assert_eq!(parse_ports("22-24,23").unwrap(), vec![22, 23, 24, 23]);
        assert_eq!(parse_ports("  22 , 80 ").unwrap(), vec![22, 80]);
    }

    #[test]
    fn parse_cidr_rejects_bad_prefixes() {
        assert!(parse_cidr("10.0.0.0/33").is_err(), "prefix > 32 must fail");
        assert!(parse_cidr("10.0.0.0/abc").is_err());
        assert!(parse_cidr("10.0.0.0/24/24").is_err());
    }

    #[test]
    fn service_names_cover_more_common_ports() {
        assert_eq!(service_name(21), "ftp");
        assert_eq!(service_name(25), "smtp");
        assert_eq!(service_name(53), "dns");
        assert_eq!(service_name(445), "microsoft-ds");
        assert_eq!(service_name(3306), "mysql");
        assert_eq!(service_name(0), "unknown");
    }
}
