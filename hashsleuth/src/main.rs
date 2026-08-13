//! HashSleuth — hash identification + password cracking toolkit.
//!
//! Modes:
//!   identify  <hash>          — fingerprint the hash type
//!   dict      <hash> <file>   — parallel dictionary attack (MD5/SHA1/SHA256)
//!   brute     <hash> <charset> <maxlen> — masked brute force (MD5/SHA1/SHA256)

use std::env;
use std::fs;
use std::io::BufRead;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

const VERSION: &str = "1.0.0";

/// Identify the hash algorithm from its encoding and length.
fn identify(hash: &str) -> Vec<String> {
    let h = hash.trim();
    let lower = h.to_lowercase();
    let mut out = Vec::new();

    if lower.starts_with("$2a$") || lower.starts_with("$2b$") || lower.starts_with("$2y$") {
        out.push("bcrypt ($2a/$2b/$2y$)".into());
    }
    if lower.starts_with("$5$") {
        out.push("sha256-crypt ($5$)".into());
    }
    if lower.starts_with("$6$") {
        out.push("sha512-crypt ($6$)".into());
    }
    if lower.starts_with("$1$") {
        out.push("md5-crypt ($1$)".into());
    }
    if lower.starts_with("$apr1$") {
        out.push("Apache MD5 ($apr1$)".into());
    }
    // phpass markers can be upper- or lower-case; `lower` is lowercase.
    if lower.starts_with("$p$") || lower.starts_with("$h$") {
        out.push("phpass (WordPress/Drupal)".into());
    }
    if lower.starts_with("{sha1}") {
        out.push("LDAP {SHA1}".into());
    }
    if lower.starts_with("{ssha}") {
        out.push("LDAP {SSHA}".into());
    }
    if lower.starts_with("pbkdf2:sha256:") {
        out.push("Django PBKDF2-SHA256".into());
    }
    if lower.starts_with("sha1$") || lower.starts_with("sha256$") {
        out.push("Django salted SHA".into());
    }

    // Hex-encoded message digests.
    let hex_only = h.chars().all(|c| c.is_ascii_hexdigit());
    if hex_only {
        match h.len() {
            32 => {
                out.push("MD5".into());
                out.push("NTLM (hex MD4)".into());
                out.push("MySQL323".into());
            }
            40 => {
                out.push("SHA1".into());
                out.push("MySQL5".into());
            }
            56 => out.push("SHA224".into()),
            64 => {
                out.push("SHA256".into());
                out.push("RIPEMD-160 (hex)".into());
            }
            96 => out.push("SHA384".into()),
            128 => out.push("SHA512".into()),
            16 => out.push("CRC32 / NTLM (hex)".into()),
            8 => out.push("CRC16 / FNV (hex)".into()),
            _ => {}
        }
    }
    if out.is_empty() {
        out.push("unknown format".into());
    }
    out
}

fn md5_hex(data: &[u8]) -> String {
    let digest = md5::compute(data);
    format!("{digest:x}")
}

fn sha1_hex(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Which algorithms to try for a given target.
fn hash_with(algo: &str, data: &[u8]) -> String {
    match algo {
        "md5" => md5_hex(data),
        "sha1" => sha1_hex(data),
        "sha256" => sha256_hex(data),
        _ => unreachable!(),
    }
}

fn dict_mode(target: &str, wordlist: &str, algo: &str) {
    let file = match fs::File::open(wordlist) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: cannot read wordlist: {e}");
            std::process::exit(1);
        }
    };
    let reader = std::io::BufReader::new(file);
    let start = Instant::now();
    let found = Arc::new(AtomicBool::new(false));
    let target_arc = target.to_string();

    let workers = num_cpus::get().max(2).min(32);
    let mut handles = Vec::new();
    let mut seen = 0usize;
    for line in reader.lines() {
        if found.load(Ordering::Relaxed) {
            break;
        }
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let candidate = line.trim();
        if candidate.is_empty() {
            continue;
        }
        seen += 1;
        let found = found.clone();
        let target = target_arc.clone();
        let algo = algo.to_string();
        let candidate = candidate.to_string();
        handles.push(thread::spawn(move || {
            if !found.load(Ordering::Relaxed)
                && hash_with(&algo, candidate.as_bytes()) == target
            {
                println!("[+] FOUND: {candidate}");
                found.store(true, Ordering::Relaxed);
            }
        }));
        if handles.len() >= workers {
            let h = handles.remove(0);
            let _ = h.join();
        }
    }
    for h in handles {
        let _ = h.join();
    }
    if !found.load(Ordering::Relaxed) {
        println!("[-] not found in {seen} words ({:.2}s)", start.elapsed().as_secs_f32());
    } else {
        println!("[*] cracked in {:.2}s", start.elapsed().as_secs_f32());
    }
}

fn brute_mode(target: &str, charset: &str, max_len: usize, algo: &str) {
    println!(
        "[*] HashSleuth {VERSION} | brute force | algo={algo} | charset=\"{charset}\" | maxlen={max_len}"
    );
    println!("[*] target: {target}");
    let start = Instant::now();
    let found = Arc::new(AtomicBool::new(false));
    let chars: Vec<char> = charset.chars().collect();
    if chars.is_empty() || max_len == 0 {
        eprintln!("error: non-empty charset and maxlen >= 1 required");
        std::process::exit(1);
    }
    let workers = num_cpus::get().max(2).min(32);
    let mut handles = Vec::new();
    let target_arc = target.to_string();
    let algo_arc = algo.to_string();

    // Parallelize across the first character of the first length.
    for w in 0..workers {
        let found = found.clone();
        let target = target_arc.clone();
        let algo = algo_arc.clone();
        let chars = chars.clone();
        handles.push(thread::spawn(move || {
            // length 1..=max_len
            for len in 1..=max_len {
                if found.load(Ordering::Relaxed) {
                    return;
                }
                let mut buf = vec![chars[0]; len];
                let total: usize = match chars.len().checked_pow(len as u32) {
                    Some(t) if t <= 100_000_000 => t,
                    _ => {
                        eprintln!("[-] search space too large (charset^{len}); aborting");
                        return;
                    }
                };
                let mut i = w;
                while i < total {
                    if found.load(Ordering::Relaxed) {
                        return;
                    }
                    // Decode index i into charset digits.
                    let mut idx = i;
                    for pos in (0..len).rev() {
                        buf[pos] = chars[idx % chars.len()];
                        idx /= chars.len();
                    }
                    let candidate: String = buf.iter().collect();
                    if hash_with(&algo, candidate.as_bytes()) == target {
                        println!("[+] FOUND: {candidate}");
                        found.store(true, Ordering::Relaxed);
                        return;
                    }
                    i += workers;
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    if !found.load(Ordering::Relaxed) {
        println!("[-] not cracked within maxlen={max_len} ({:.2}s)", start.elapsed().as_secs_f32());
    } else {
        println!("[*] cracked in {:.2}s", start.elapsed().as_secs_f32());
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        println!(
            "HashSleuth {VERSION} — hash identification & password cracking\n\
             \n\
             USAGE:\n  hashsleuth identify <hash>\n  hashsleuth dict <hash> <wordlist> [--algo md5|sha1|sha256]\n  hashsleuth brute <hash> <charset> <maxlen> [--algo md5|sha1|sha256]\n\
             \n\
             EXAMPLES:\n  hashsleuth identify 5f4dcc3b5aa765d61d8327deb882cf99\n  hashsleuth dict 5f4dcc3b5aa765d61d8327deb882cf99 rockyou.txt\n  hashsleuth brute 5f4dcc3b5aa765d61d8327deb882cf99 abc123 5 --algo md5"
        );
        return;
    }

    match args[0].as_str() {
        "identify" => {
            let hash = args.get(1).expect("usage: hashsleuth identify <hash>");
            let results = identify(hash);
            println!("[*] hash: {hash}");
            for r in &results {
                println!("[?] possible: {r}");
            }
        }
        "dict" => {
            let hash = args.get(1).expect("usage: hashsleuth dict <hash> <wordlist>");
            let wordlist = args.get(2).expect("usage: hashsleuth dict <hash> <wordlist>");
            let mut algo = String::new();
            let mut i = 3;
            while i < args.len() {
                if args[i] == "--algo" {
                    if let Some(a) = args.get(i + 1) {
                        algo = a.clone();
                    }
                }
                i += 1;
            }
            if algo.is_empty() {
                let guesses = identify(hash);
                algo = if hash.len() == 32 {
                    "md5".into()
                } else if hash.len() == 40 {
                    "sha1".into()
                } else if hash.len() == 64 {
                    "sha256".into()
                } else {
                    eprintln!("cannot auto-detect algo for len {}; pass --algo", hash.len());
                    std::process::exit(1);
                };
                println!("[*] auto-detected algo: {algo} (from {})", guesses.first().unwrap_or(&"?".to_string()));
            }
            dict_mode(hash, wordlist, &algo);
        }
        "brute" => {
            let hash = args.get(1).expect("usage: hashsleuth brute <hash> <charset> <maxlen>");
            let charset = args.get(2).expect("usage: hashsleuth brute <hash> <charset> <maxlen>");
            let maxlen: usize = args
                .get(3)
                .and_then(|v| v.parse().ok())
                .expect("usage: hashsleuth brute <hash> <charset> <maxlen>");
            let mut algo = String::new();
            let mut i = 4;
            while i < args.len() {
                if args[i] == "--algo" {
                    if let Some(a) = args.get(i + 1) {
                        algo = a.clone();
                    }
                }
                i += 1;
            }
            if algo.is_empty() {
                algo = if hash.len() == 32 {
                    "md5".into()
                } else if hash.len() == 40 {
                    "sha1".into()
                } else if hash.len() == 64 {
                    "sha256".into()
                } else {
                    eprintln!("cannot auto-detect algo; pass --algo");
                    std::process::exit(1);
                };
            }
            brute_mode(hash, charset, maxlen, &algo);
        }
        other => eprintln!("unknown command: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_known_hex_digests() {
        let md5 = identify("5f4dcc3b5aa765d61d8327deb882cf99");
        assert!(md5.iter().any(|s| s.contains("MD5")), "{md5:?}");
        let sha256 = identify("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert!(sha256.iter().any(|s| s.contains("SHA256")), "{sha256:?}");
        let sha512 = identify("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        // 128 hex chars -> SHA512 family.
        assert!(sha512.iter().any(|s| s.contains("SHA512")), "{sha512:?}");
    }

    #[test]
    fn identify_crypt_prefixes() {
        let bcrypt = identify("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy");
        assert!(bcrypt.iter().any(|s| s.contains("bcrypt")), "{bcrypt:?}");
        let phpass = identify("$P$B5EhV6fL9pVlT7q8zYyGxJ3m2rWvU0k1");
        assert!(phpass.iter().any(|s| s.contains("phpass")), "{phpass:?}");
    }

    #[test]
    fn unknown_format_is_reported() {
        assert_eq!(identify("zzz-not-a-hash"), vec!["unknown format"]);
    }

    #[test]
    fn digest_helpers_match_known_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"hello"), "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(
            sha1_hex(b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hash_with("md5", b"hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn identify_more_hex_lengths() {
        // 40 hex chars -> SHA1 family; 96 -> SHA384.
        let sha1 = identify("a9993e364706816aba3e25717850c26c9cd0d89d");
        assert!(sha1.iter().any(|s| s.contains("SHA1")), "{sha1:?}");
        let sha224 = identify(&"ab".repeat(28));
        assert!(sha224.iter().any(|s| s.contains("SHA224")), "{sha224:?}");
        let sha384 = identify(&"ab".repeat(48));
        assert!(sha384.iter().any(|s| s.contains("SHA384")), "{sha384:?}");
        let crc16 = identify(&"ab".repeat(4));
        assert!(crc16.iter().any(|s| s.contains("CRC16")), "{crc16:?}");
    }

    #[test]
    fn identify_crypt_and_django_prefixes() {
        let sha256_crypt = identify("$5$rounds=535000$wBcWwLeRbvNMf8hS$ylXEmvNHYJNgbYvSX4uqhO3kUo1pX9vN2");
        assert!(sha256_crypt.iter().any(|s| s.contains("sha256-crypt")), "{sha256_crypt:?}");
        let sha512_crypt = identify("$6$rounds=656000$hQdFQj6Gz0nQk1rQ$vQFZPk0lM4q5wJ2tV7sNqB1uD3fH8yW2");
        assert!(sha512_crypt.iter().any(|s| s.contains("sha512-crypt")), "{sha512_crypt:?}");
        let md5_crypt = identify("$1$salt$hashstring");
        assert!(md5_crypt.iter().any(|s| s.contains("md5-crypt")), "{md5_crypt:?}");
        let ldap = identify("{SHA1}base64encodeddigest");
        assert!(ldap.iter().any(|s| s.contains("LDAP")), "{ldap:?}");
        let django = identify("pbkdf2:sha256:100000$salt$hash");
        assert!(django.iter().any(|s| s.contains("Django")), "{django:?}");
    }

    #[test]
    fn phpass_uppercase_markers_are_recognized() {
        // WordPress ($P$) and Drupal ($H$) markers must both match.
        assert!(identify("$P$B5EhV6fL9pVlT7q8zYyGxJ3m2rWvU0k1").iter().any(|s| s.contains("phpass")));
        assert!(identify("$H$B5EhV6fL9pVlT7q8zYyGxJ3m2rWvU0k1").iter().any(|s| s.contains("phpass")));
    }

    #[test]
    fn identify_trims_whitespace() {
        let clean = identify("d41d8cd98f00b204e9800998ecf8427e");
        let padded = identify("  d41d8cd98f00b204e9800998ecf8427e \t");
        assert_eq!(padded, clean);
    }
}
