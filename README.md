<img src="https://capsule-render.vercel.app/api?type=cylinder&color=0:0d1117,50:2ea043,100:a3d6ff&height=140&section=header&text=Cybersec%20Tools&fontSize=36&fontColor=fff&desc=four%20Rust%20security%20tools%20%C2%B7%20recon%20%C2%B7%20web%20%C2%B7%20crypto%20%C2%B7%20packets&descSize=15&descAlignY=72" width="100%" />


[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/BartoszOsiej/cybersec-tools/badge)](https://scorecard.dev/viewer/?uri=github.com/BartoszOsiej/cybersec-tools)

<div align="center">

[![crates.io](https://img.shields.io/crates/v/netrecon?style=for-the-badge&logo=rust&label=netrecon)](https://crates.io/crates/netrecon)
[![crates.io](https://img.shields.io/crates/v/shadowscan?style=for-the-badge&logo=rust&label=shadowscan)](https://crates.io/crates/shadowscan)
[![crates.io](https://img.shields.io/crates/v/hashsleuth?style=for-the-badge&logo=rust&label=hashsleuth)](https://crates.io/crates/hashsleuth)
[![crates.io](https://img.shields.io/crates/v/packeteye?style=for-the-badge&logo=rust&label=packeteye)](https://crates.io/crates/packeteye)
[![GHCR](https://img.shields.io/badge/GHCR-image-2496ED?style=for-the-badge&logo=docker)](https://github.com/BartoszOsiej/cybersec-tools/pkgs/container/cybersec-tools)
[![Release](https://img.shields.io/badge/release-4%20binaries-8A2BE2?style=for-the-badge&logo=github)](https://github.com/BartoszOsiej/cybersec-tools/releases)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)

**A Rust workspace of four single-purpose security tools.** Each tool is a
standalone binary with no shared runtime; everything builds from the workspace root.

</div>

| Tool | Mission |
|---|---|
| 🔍 **[`netrecon`](https://crates.io/crates/netrecon)** | Asynchronous TCP port scanner + banner grabbing + service fingerprinting |
| 🕸️ **[`shadowscan`](https://crates.io/crates/shadowscan)** | Web vulnerability scanner: header audit, TLS checks, SQLi/XSS probes, path discovery |
| 🔑 **[`hashsleuth`](https://crates.io/crates/hashsleuth)** | Hash identifier, dictionary cracker, masked brute-forcer |
| 📡 **[`packeteye`](https://crates.io/crates/packeteye)** | Packet capture analyzer: live sniffing + offline pcap parsing with protocol stats |

## Build

```bash
cargo build --release
# binaries: target/release/{netrecon,shadowscan,hashsleuth,packeteye}
```

Release profile is tuned for size and speed: full LTO, `opt-level = 3`, symbol stripping.

## 🎮 Run the tools from a GitHub comment

Comment on [the Playground issue](https://github.com/BartoszOsiej/cybersec-tools/issues/10):

```
/run hashsleuth identify 5f4dcc3b5aa765d61d8327deb882cf99
/run netrecon 127.0.0.1 22,80,443
```

The bot builds the workspace in an isolated runner, executes with a 60 s timeout and posts the output back. Guardrails: whitelisted tools · strict argument charset · netrecon loopback-only · brute capped at `maxlen ≤ 6`.

## 📺 Live terminal demos

Rendered reproducibly in CI from [`vhs` tapes](.github/vhs/) — what you see is what the binaries actually print:

| hashsleuth | netrecon |
|---|---|
| ![hashsleuth demo](assets/demo-hashsleuth.svg) | ![netrecon demo](assets/demo-netrecon.svg) |


## 🔏 Verify a release yourself

```bash
./verify.sh v0.4.5
```

One command checks SLSA build provenance (`gh attestation verify`), Sigstore keyless signatures (`cosign verify`) and unpacks the SPDX SBOM. No trust required — everything is reproducible from public logs.

<a href="https://codespaces.new/BartoszOsiej/cybersec-tools?devcontainer_path=.devcontainer/devcontainer.json">
  <img src="https://github.com/codespaces/badge.svg" alt="Open in GitHub Codespaces" />
</a>

<details>
<summary><b>🔍 netrecon — port scanner</b></summary>

```bash
netrecon <target> [--ports 1-1000] [--timeout 1000]
```

- Asynchronous TCP connect scanning
- Banner grabbing on open ports
- Service fingerprinting

</details>

<details>
<summary><b>🕸️ shadowscan — web scanner</b></summary>

```bash
shadowscan <url>
```

- Security header audit (`Strict-Transport-Security`, `X-Frame-Options`, CSP, …)
- TLS certificate checks
- SQLi / XSS reflection probes
- Common-path discovery

</details>

<details>
<summary><b>🔑 hashsleuth — hash analysis</b></summary>

```bash
hashsleuth <hash>
hashsleuth <hash> --dict wordlist.txt
hashsleuth <hash> --bruteforce --charset abc123 --max-len 6
```

- Hash type identification (MD5, SHA-1, SHA-256, …)
- Dictionary cracking
- Masked brute-force with custom charsets

</details>

<details>
<summary><b>📡 packeteye — packet analysis</b></summary>

```bash
packeteye -i eth0            # live capture
packeteye -r capture.pcap    # offline pcap analysis
```

- Live packet sniffing
- Offline pcap parsing
- Per-protocol statistics

</details>

> [!CAUTION]
> These are security tools by design. Use them only on systems and networks you
> own or are explicitly authorized to test. Unauthorized scanning or probing may
> be illegal in your jurisdiction.

---

<div align="center">

**Part of [BartoszOsiej](https://github.com/BartoszOsiej)'s security stack** · [`halcyon-process-monitor`](https://github.com/BartoszOsiej/halcyon-process-monitor) — eBPF ransomware tracker

MIT © 2026 Bartosz Osiej

</div>
