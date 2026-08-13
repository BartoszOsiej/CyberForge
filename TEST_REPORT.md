# Cybersec Toolkit — Test Report & QA

> Generated: 2026-08-13 · Rust `cargo 1.97.1` · Linux
> Re-run: `cargo test --workspace`

## Whole project

**✅ 13 tests · 0 failed** across the 4 crates.

## Per-crate

| Crate | Tests | Status |
|---|---|---|
| `hashsleuth` | 4 — hash identification, MD5/SHA1/SHA256 known-answer vectors | ✅ |
| `netrecon` | 4 — service names, port range parsing, CIDR expansion, single-IP | ✅ |
| `packeteye` | 3 — synthetic Ethernet/IPv4/TCP-SYN parse, garbage safety, ICMP counting | ✅ |
| `shadowscan` | 2 — target URL normalization | ✅ |

## Findings

- **Fixed real bug:** phpass markers (`$P$`/`$H$`) were compared against the
  lowercased hash string and could never match → detection now works.
- Clippy (`cargo clippy --all-targets`): no warnings introduced.
- The 4 crates previously had **zero** unit tests; this report adds the
  first coverage.
