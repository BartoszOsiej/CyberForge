# Cybersec Toolkit — Test Report & QA

> Generated: 2026-08-13 · Rust `cargo 1.97.1` · Linux
> Re-run: `cargo test --workspace`

## Whole project

**✅ 29 tests · 0 failed** across the 4 crates.

## Per-crate

| Crate | Tests | Status |
|---|---|---|
| `hashsleuth` | 8 — hash identification (hex lengths, crypt/Django/LDAP/phpass prefixes), known-answer vectors | ✅ |
| `netrecon` | 8 — service names, ports/ranges, CIDR expansion + rejection, invalid forms | ✅ |
| `packeteye` | 8 — TCP SYN/SYNACK/FIN, UDP ports, ICMP, ARP, IPv6 skip, garbage safety | ✅ |
| `shadowscan` | 5 — target normalization incl. ports, queries, schemes, whitespace | ✅ |

## Findings

- **Fixed real bug:** phpass markers (`$P$`/`$H$`) were compared against the
  lowercased hash string and could never match → detection now works.
- Clippy (`cargo clippy --all-targets`): no warnings introduced.
- The 4 crates previously had **zero** unit tests; this report adds the
  first coverage (13 → 29 tests in the 2026-08-13 sweep).
