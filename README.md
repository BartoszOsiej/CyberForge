# Cybersec Tools

[![CI](https://github.com/BartoszOsiej/cybersec-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/BartoszOsiej/cybersec-tools/actions)

A Rust workspace of four small, single-purpose security tools — network
reconnaissance, web scanning, hash analysis, and packet inspection. Each tool
is a standalone binary with no shared runtime; everything builds from the
workspace root.

```
cybersec-tools/
├── netrecon/      Asynchronous TCP port scanner + banner grabbing + service fingerprinting
├── shadowscan/    Web vulnerability scanner: header audit, TLS checks, SQLi/XSS probes, path discovery
├── hashsleuth/    Hash identifier, dictionary cracker, masked brute-forcer
└── packeteye/     Packet capture analyzer: live sniffing + offline pcap parsing with protocol stats
```

## Build

```bash
cargo build --release
# binaries: target/release/{netrecon,shadowscan,hashsleuth,packeteye}
```

Release profile is tuned for size and speed: full LTO, `opt-level = 3`,
symbol stripping.

## Tools

### netrecon — port scanner

```bash
netrecon <target> [--ports 1-1000] [--timeout 1000]
```

- Asynchronous TCP connect scanning
- Banner grabbing on open ports
- Service fingerprinting

### shadowscan — web scanner

```bash
shadowscan <url>
```

- Security header audit (`Strict-Transport-Security`, `X-Frame-Options`, CSP, …)
- TLS certificate checks
- SQLi / XSS reflection probes
- Common-path discovery

### hashsleuth — hash analysis

```bash
hashsleuth <hash>
hashsleuth <hash> --dict wordlist.txt
hashsleuth <hash> --bruteforce --charset abc123 --max-len 6
```

- Hash type identification (MD5, SHA-1, SHA-256, …)
- Dictionary cracking
- Masked brute-force with custom charsets

### packeteye — packet analysis

```bash
packeteye -i eth0            # live capture
packeteye -r capture.pcap    # offline pcap analysis
```

- Live packet sniffing
- Offline pcap parsing
- Per-protocol statistics

## Security note

These are security tools by design. Use them only on systems and networks you
own or are explicitly authorized to test. Unauthorized scanning or probing may
be illegal in your jurisdiction.
