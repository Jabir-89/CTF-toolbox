# ctftool

Small, dependency-free helpers for **CTF challenges**, **file forensics**, and
**capture analysis** — one command instead of five half-remembered one-liners.

```text
$ ctftool decode -f base64 ZmxhZ3toZWxsb193b3JsZH0=
flag{hello_world}

$ ctftool caesar -b "Wkh txlfn eurzq ira" -t 1
[23]  -2.983  The quick brown fox
```

No network calls, no telemetry, stdlib only for the core features.

## Features

| Area | What you get |
|---|---|
| Encodings | base64 / base32 / hex / binary / URL / Morse / ROT13 / reverse, encode + decode, and `auto` mode that tries all of them |
| Classical ciphers | Caesar (with brute force), Atbash, Vigenère, rail fence, single-byte XOR (with key brute force) |
| Hashes | identify a dozen formats by shape, crack against a wordlist with `hashlib` or `hashcat` |
| File forensics | type by magic bytes, MD5/SHA1/SHA256, printable strings with byte offsets |
| Captures | classic pcap summary without tshark, deauth/disassoc summary with it, WPA handshake → `.hc22000` |

## Install

```bash
git clone https://github.com/Jabir-89/CTF-toolbox.git
cd ctf-toolbox
pip install -e .          # or: pipx install .
ctftool --help
```

Python 3.9+. No required third-party packages.

## Usage

### Encodings

```bash
ctftool encode -f base64 "hello"          # aGVsbG8=
ctftool decode -f base64 "aGVsbG8="       # hello
ctftool decode "aGVsbG8="                 # auto: tries every scheme
ctftool decode "68656c6c6f" -f hex
ctftool encode -f binary "A"              # 01000001
ctftool encode -f morse "SOS"             # ... --- ...
echo "ZmxhZ3thYmN9" | ctftool decode -
```

### Ciphers

```bash
ctftool caesar "Khoor Zruog" -s -3        # Hello World
ctftool caesar -b "Wkh txlfn eurzq ira"   # rank all 25 shifts
ctftool atbash "Uryyb"
ctftool vigenere "LXFOPVEFRNHR" -k LEMON -d   # ATTACKATDAWN
ctftool railfence -d "WECRLTEERDSOEEFEAOCAIVDEN" -r 3
ctftool xor -k 0x5a "cipher text"
ctftool xor -b "cipher text"              # try all 256 keys, scored by English
```

### Hashes

```bash
ctftool hashid 5d41402abc4b2a76b9719d911017c592
ctftool crack 5d41402abc4b2a76b9719d911017c592 -w /usr/share/wordlists/rockyou.txt
ctftool crack '$2b$12$...' -w words.txt -e hashcat -m 3200
```

The `python` engine covers md5/sha1/sha2 and is slow on purpose — use `hashcat`
when it is installed and the search space is real.

### Files

```bash
ctftool file suspicious.png
ctftool strings suspicious.png -n 6
ctftool strings firmware.bin -l 20
```

### Captures

```bash
ctftool pcap capture.pcap
ctftool pcap capture.pcap --deauth      # needs tshark
ctftool wifi-hash capture.pcap -o out.hc22000   # needs hcxtools
```

## Why this exists

CTF tooling tends to be either a 4,000-line framework or a folder of unnamed
one-liners. This is the third option: a small, tested CLI where each subcommand
does one thing, prints in a copy-pasteable format, and has a unit test.

It is also a learning project — every module is short enough to read end to end.

## Project layout

```text
ctf-toolbox/
├── ctftool/
│   ├── cli.py           # argparse subcommands
│   ├── encodings.py     # base64, hex, morse, auto-detect
│   ├── ciphers.py       # caesar, vigenere, rail fence, xor + scoring
│   ├── hashes.py        # identify + crack (hashlib / hashcat)
│   ├── files.py         # magic bytes, digests, strings
│   └── netforensics.py  # pcap parsing, deauth summary, WPA hash
├── tests/               # stdlib unittest, runs on 3.9–3.12
└── .github/workflows/   # CI: tests + CLI smoke test on every push
```

## Development

```bash
python -m unittest discover -s tests -v
```

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

- [ ] `ctftool image` — PNG chunk walker, LSB extract, EXIF dump
- [ ] `ctftool jwt` — decode and inspect JWT claims
- [ ] `ctftool snow` — steganography in trailing whitespace
- [ ] `--json` output for every command
- [ ] shell completions

## Ethics

Everything here is for **CTF challenges, your own files, and your own captures**.
Analysing traffic you did not collect, or files you are not authorized to examine,
is not a use case this project supports.

## License

MIT — see [LICENSE](LICENSE).
