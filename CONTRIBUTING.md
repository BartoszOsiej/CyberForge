# Contributing to Cybersec Tools

Thanks for your interest in improving these security tools!

## Quick Start

```bash
git clone https://github.com/BartoszOsiej/cybersec-tools.git
cd cybersec-tools
cargo build --release
cargo test
```

## Ways to Contribute

### 🐛 Bug Reports
Open an issue with:
- Tool name and version
- Steps to reproduce
- Expected vs actual behavior
- OS and Rust version

### 🔍 New Detection Rules
Each tool accepts community-contributed rules:
- **shadowscan** — new header checks, vulnerability patterns
- **hashsleuth** — new hash type signatures
- **netrecon** — new service fingerprints
- **packeteye** — new protocol dissectors

### ✨ New Features
1. Fork the repo
2. Create a branch: `git checkout -b feat/my-feature`
3. Add tests in each tool's `tests/` directory
4. Run: `cargo test --workspace`
5. Open a PR

## Code Style

- **Rust 2021 edition**
- **Tokio** for async code
- **Clippy clean** — `cargo clippy --workspace -- -D warnings`
- **Formatted** — `cargo fmt --all`

## Security

These are security tools. Never:
- Add exploit code for real vulnerabilities
- Include credentials or API keys
- Scan systems without authorization

## License

MIT
