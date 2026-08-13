# Cybersec Tools

Workspace Rust z czterema małymi, jednozadaniowymi narzędziami
bezpieczeństwa — rozpoznanie sieci, skanowanie web, analiza hashów i inspekcja
pakietów. Każde narzędzie to osobny binarny plik bez wspólnego runtime;
wszystko buduje się z głównego katalogu workspace'a.

```
cybersec-tools/
├── netrecon/      Asynchroniczny skaner portów TCP + zbieranie banerów + fingerprinting usług
├── shadowscan/    Skaner podatności web: audyt nagłówków, kontrole TLS, próbniki SQLi/XSS, odkrywanie ścieżek
├── hashsleuth/    Identyfikator hashów, łamacz słownikowy, brute-force z maską
└── packeteye/     Analizator przechwyconych pakietów: podgląd na żywo + parsowanie pcap offline ze statystykami protokołów
```

## Budowanie

```bash
cargo build --release
# binarki: target/release/{netrecon,shadowscan,hashsleuth,packeteye}
```

Profil release jest zoptymalizowany pod rozmiar i szybkość: pełne LTO,
`opt-level = 3`, usuwanie symboli.

## Narzędzia

### netrecon — skaner portów

```bash
netrecon <cel> [--ports 1-1000] [--timeout 1000]
```

- Asynchroniczne skanowanie portów TCP (connect)
- Zbieranie banerów na otwartych portach
- Fingerprinting usług

### shadowscan — skaner web

```bash
shadowscan <url>
```

- Audyt nagłówków bezpieczeństwa (`Strict-Transport-Security`, `X-Frame-Options`, CSP, …)
- Kontrole certyfikatów TLS
- Próbniki refleksji SQLi / XSS
- Odkrywanie popularnych ścieżek

### hashsleuth — analiza hashów

```bash
hashsleuth <hash>
hashsleuth <hash> --dict wordlist.txt
hashsleuth <hash> --bruteforce --charset abc123 --max-len 6
```

- Identyfikacja typu hasha (MD5, SHA-1, SHA-256, …)
- Łamanie słownikowe
- Brute-force z maską i własnymi zestawami znaków

### packeteye — analiza pakietów

```bash
packeteye -i eth0            # przechwytywanie na żywo
packeteye -r capture.pcap    # analiza pcap offline
```

- Podgląd pakietów na żywo
- Parsowanie pcap offline
- Statystyki per protokół

## Uwaga o bezpieczeństwie

To narzędzia bezpieczeństwa z założenia. Używaj ich wyłącznie na systemach
i sieciach, które posiadasz lub do testowania których masz wyraźne
upoważnienie. Nieautoryzowane skanowanie może być nielegalne w Twojej
jurysdykcji.
