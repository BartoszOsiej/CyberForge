# 🔒 Cybersec Tools

![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Rust](https://img.shields.io/badge/Rust-2021-DEA584?style=flat-square&logo=rust)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/BartoszOsiej/cybersec-tools/badge)](https://securityscorecards.dev/viewer/?uri=github.com/BartoszOsiej/cybersec-tools)
![crates.io](https://img.shields.io/crates/v/netrecon?style=flat-square&label=netrecon&logo=rust)
![crates.io](https://img.shields.io/crates/v/shadowscan?style=flat-square&label=shadowscan&logo=rust)
![crates.io](https://img.shields.io/crates/v/hashsleuth?style=flat-square&label=hashsleuth&logo=rust)
![crates.io](https://img.shields.io/crates/v/packeteye?style=flat-square&label=packeteye&logo=rust)
![Docker](https://img.shields.io/badge/Docker-GHCR-2496ED?style=flat-square&logo=docker)

**A Rust workspace of four small, single-purpose security tools — network
reconnaissance, web scanning, hash analysis, and packet inspection.**

> 🇵🇱 [Wersja polska](README.pl.md) · [Documentation](https://bartoszosiej.github.io/Docs/projects/cybersec-tools/)

---

## Table of Contents

- [Tools](#tools)
- [Quick Start](#quick-start)
- [Tool Details](#tool-details)
- [Build](#build)
- [Docker](#docker)
- [Security Note](#security-note)
- [License](#license)

---

## Tools

```
cybersec-tools/
├── netrecon/      TCP port scanner + banner grabbing + service fingerprinting
├── shadowscan/    Web vulnerability scanner: header audit, TLS, SQLi/XSS probes
├── hashsleuth/    Hash identifier, dictionary cracker, masked brute-forcer
└── packeteye/     Packet capture analyzer: live sniffing + offline pcap parsing
```

---

## Quick Start

```bash
# Install from crates.io
cargo install netrecon shadowscan hashsleuth packeteye

# Or build from source
git clone https://github.com/BartoszOsiej/cybersec-tools.git
cd cybersec-tools
cargo build --release

# Binaries: target/release/{netrecon,shadowscan,hashsleuth,packeteye}
```

---

## Tool Details

### 🔍 netrecon — Port Scanner

```bash
netrecon <target> [--ports 1-1000] [--timeout 1000]
```

| Feature | Description |
|---|---|
| Async TCP scan | Tokio-based concurrent port scanning |
| Banner grabbing | Reads service banners on open ports |
| Service fingerprinting | Identifies running services from banners |

### 🕵️ shadowscan — Web Scanner

```bash
shadowscan <url>
```

| Feature | Description |
|---|---|
| Header audit | HSTS, X-Frame-Options, CSP, and more |
| TLS checks | Certificate validity, protocol versions |
| SQLi/XSS probes | Reflection-based vulnerability detection |
| Path discovery | Common admin/debug path enumeration |

### 🔑 hashsleuth — Hash Analysis

```bash
hashsleuth <hash>
hashsleuth <hash> --dict wordlist.txt
hashsleuth <hash> --bruteforce --charset abc123 --max-len 6
```

| Feature | Description |
|---|---|
| Type identification | MD5, SHA-1, SHA-256, bcrypt, and more |
| Dictionary cracking | Wordlist-based attack |
| Masked brute-force | Custom charsets, configurable length |

### 📡 packeteye — Packet Analysis

```bash
packeteye -i eth0            # live capture
packeteye -r capture.pcap    # offline pcap analysis
```

| Feature | Description |
|---|---|
| Live sniffing | Real-time packet capture on interfaces |
| Offline parsing | pcap file analysis |
| Protocol stats | Per-protocol breakdown and statistics |

---

## Build

```bash
cargo build --release
```

Release profile: full LTO, `opt-level = 3`, symbol stripping — optimized for
size and speed.

---

## Docker

```bash
# Build
docker build -t cybersec-tools .

# Run netrecon
docker run --rm cybersec-tools netrecon scanme.nmap.org

# Run hashsleuth
docker run --rm cybersec-tools hashsleuth 5d41402abc4b2a76b9719d911017c592
```

---

## Security Note

These are security tools by design. Use them only on systems and networks you
own or are explicitly authorized to test. Unauthorized scanning or probing may
be illegal in your jurisdiction.

---

## License

MIT

---
