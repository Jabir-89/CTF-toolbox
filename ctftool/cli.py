"""Command-line interface for ctftool."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, ciphers, encodings, files, hashes, netforensics, solver


def _read_text(values: list[str]) -> str:
    """Join positional words, or read stdin when the argument is '-'."""
    if values == ["-"]:
        return sys.stdin.read().rstrip("\n")
    return " ".join(values)


def _print_results(pairs: list[tuple[str, str]]) -> None:
    if not pairs:
        print("[-] no readable decoding found")
        return
    for name, value in pairs:
        print(f"[{name}] {value}")


# ---------------------------------------------------------------- commands

def cmd_encode(args: argparse.Namespace) -> int:
    text = _read_text(args.text)
    try:
        print(encodings.ENCODERS[args.format](text))
    except KeyError:
        print(f"[!] unknown format: {args.format}", file=sys.stderr)
        return 2
    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    text = _read_text(args.text)
    if args.format == "auto":
        _print_results(encodings.auto_decode(text))
        return 0
    try:
        print(encodings.DECODER_MAP[args.format](text))
    except KeyError:
        print(f"[!] unknown format: {args.format}", file=sys.stderr)
        return 2
    except (ValueError, Exception) as exc:  # noqa: BLE001 - report, don't crash
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_caesar(args: argparse.Namespace) -> int:
    text = _read_text(args.text)
    if args.brute:
        for shift, candidate, score in ciphers.caesar_bruteforce(text)[:args.top]:
            print(f"[{shift:2d}] {score:7.3f}  {candidate}")
        return 0
    print(ciphers.caesar(text, args.shift))
    return 0


def cmd_xor(args: argparse.Namespace) -> int:
    text = _read_text(args.text)
    if args.brute:
        for key, candidate, score in ciphers.xor_bruteforce(text, args.top):
            print(f"[0x{key:02x}] {score:7.3f}  {candidate}")
        return 0
    if args.key is None:
        print("[!] give --key 0xNN or --brute", file=sys.stderr)
        return 2
    print(ciphers.xor_single(text, args.key))
    return 0


def cmd_vigenere(args: argparse.Namespace) -> int:
    print(ciphers.vigenere(_read_text(args.text), args.key, decrypt=args.decrypt))
    return 0


def cmd_atbash(args: argparse.Namespace) -> int:
    print(ciphers.atbash(_read_text(args.text)))
    return 0


def cmd_railfence(args: argparse.Namespace) -> int:
    text = _read_text(args.text)
    fn = ciphers.railfence_decode if args.decode else ciphers.railfence_encode
    print(fn(text, args.rails))
    return 0


def cmd_hashid(args: argparse.Namespace) -> int:
    guesses = hashes.identify(_read_text(args.hash))
    if not guesses:
        print("[-] no common signature matched")
        return 1
    for name, mode in guesses:
        print(f"{name:12s} hashcat mode {mode}")
    return 0


def cmd_crack(args: argparse.Namespace) -> int:
    digest = _read_text(args.hash)
    wordlist = Path(args.wordlist).expanduser()
    if not wordlist.is_file():
        print(f"[!] wordlist not found: {wordlist}", file=sys.stderr)
        return 2

    use_python = args.engine == "python" or (args.engine == "auto" and not hashes.hashcat_available())
    if use_python:
        if hashes.python_algo(digest) is None:
            print("[!] the python engine handles md5/sha1/sha2 hex digests only; "
                  "use -e hashcat for this one", file=sys.stderr)
            return 2
        plain = hashes.crack_python(digest, wordlist)
    else:
        try:
            plain = hashes.hashcat_crack(digest, wordlist, mode=args.mode, rules=args.rules)
        except RuntimeError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 3

    if plain is None:
        print("[-] not found in that wordlist")
        return 1
    print(f"[+] {plain}")
    return 0


def cmd_solve(args: argparse.Namespace) -> int:
    text = _read_text(args.text)
    data = text.encode("utf-8", "surrogateescape")
    results = solver.solve(data, max_depth=args.depth, top=args.top)
    if not results:
        print("[-] no chain produced readable text")
        return 1
    for rank, (score, chain, out) in enumerate(results, 1):
        print(f"[{rank}] {score:7.3f}  {out}")
        print(f"    chain: {chain}")
    return 0


def cmd_strings(args: argparse.Namespace) -> int:
    path = Path(args.file).expanduser()
    if not path.is_file():
        print(f"[!] not a file: {path}", file=sys.stderr)
        return 2
    hits = files.strings(path, min_len=args.min_len, limit=args.limit)
    for offset, text in hits:
        print(f"0x{offset:08x}  {text}")
    print(f"[i] {len(hits)} string(s)", file=sys.stderr)
    return 0


def cmd_file(args: argparse.Namespace) -> int:
    path = Path(args.file).expanduser()
    if not path.is_file():
        print(f"[!] not a file: {path}", file=sys.stderr)
        return 2
    data = files.info(path)
    for key in ("path", "type", "size", "md5", "sha1", "sha256"):
        print(f"{key:8s} {data[key]}")
    return 0


def cmd_pcap(args: argparse.Namespace) -> int:
    path = Path(args.file).expanduser()
    if not path.is_file():
        print(f"[!] not a file: {path}", file=sys.stderr)
        return 2
    try:
        summary = netforensics.pcap_summary(path)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    for key, value in summary.items():
        print(f"{key:12s} {value}")

    if args.deauth:
        frames = netforensics.deauth_frames(path)
        if frames is None:
            print("[i] tshark not installed — install wireshark-common for frame analysis")
            return 0
        print(f"\ntotal deauth/disassoc frames: {frames['total']}")
        for source, count in frames["by_source"]:
            print(f"  source {source}  {count}")
        for reason, count in frames["by_reason"]:
            print(f"  reason {reason}  {count}")
    return 0


def cmd_wifi_hash(args: argparse.Namespace) -> int:
    path = Path(args.file).expanduser()
    if not path.is_file():
        print(f"[!] not a file: {path}", file=sys.stderr)
        return 2
    try:
        out = netforensics.wpa_hash(path, Path(args.out).expanduser() if args.out else None)
    except RuntimeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 3
    if out is None:
        print("[-] no handshake or PMKID in that capture")
        return 1
    print(f"[+] {out}")
    return 0


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctftool",
        description="Small, dependency-free helpers for CTF challenges: encodings, "
                    "classical ciphers, hash identification, file and capture forensics.",
        epilog="Use only on your own files, your own captures, and CTF challenges.",
    )
    parser.add_argument("--version", action="version", version=f"ctftool {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encode", help="encode text")
    enc.add_argument("text", nargs="+", help="text to encode, or '-' for stdin")
    enc.add_argument("-f", "--format", default="base64", choices=sorted(encodings.ENCODERS))
    enc.set_defaults(func=cmd_encode)

    dec = sub.add_parser("decode", help="decode text (auto tries every scheme)")
    dec.add_argument("text", nargs="+", help="text to decode, or '-' for stdin")
    dec.add_argument("-f", "--format", default="auto",
                     choices=["auto"] + sorted(encodings.DECODER_MAP))
    dec.set_defaults(func=cmd_decode)

    sol = sub.add_parser("solve", help="search decoder/cipher chains for a flag")
    sol.add_argument("text", nargs="+", help="the encoded text, or '-' for stdin")
    sol.add_argument("-d", "--depth", type=int, default=3,
                     help="how many decoding layers to try (default 3)")
    sol.add_argument("-t", "--top", type=int, default=5, help="how many candidates to show")
    sol.set_defaults(func=cmd_solve)

    cae = sub.add_parser("caesar", help="Caesar shift, or brute-force all 25")
    cae.add_argument("text", nargs="+")
    cae.add_argument("-s", "--shift", type=int, default=3)
    cae.add_argument("-b", "--brute", action="store_true")
    cae.add_argument("-t", "--top", type=int, default=5)
    cae.set_defaults(func=cmd_caesar)

    x = sub.add_parser("xor", help="single-byte XOR, or brute-force the key")
    x.add_argument("text", nargs="+")
    x.add_argument("-k", "--key", type=lambda v: int(v, 0), default=None,
                   help="key as decimal or 0xNN")
    x.add_argument("-b", "--brute", action="store_true")
    x.add_argument("-t", "--top", type=int, default=5)
    x.set_defaults(func=cmd_xor)

    vig = sub.add_parser("vigenere", help="Vigenere cipher")
    vig.add_argument("text", nargs="+")
    vig.add_argument("-k", "--key", required=True)
    vig.add_argument("-d", "--decrypt", action="store_true")
    vig.set_defaults(func=cmd_vigenere)

    atb = sub.add_parser("atbash", help="Atbash (mirror alphabet)")
    atb.add_argument("text", nargs="+")
    atb.set_defaults(func=cmd_atbash)

    rail = sub.add_parser("railfence", help="Rail fence transposition")
    rail.add_argument("text", nargs="+")
    rail.add_argument("-r", "--rails", type=int, default=3)
    rail.add_argument("-d", "--decode", action="store_true")
    rail.set_defaults(func=cmd_railfence)

    hid = sub.add_parser("hashid", help="identify a hash type by its format")
    hid.add_argument("hash", nargs="+")
    hid.set_defaults(func=cmd_hashid)

    crk = sub.add_parser("crack", help="crack a hash against a wordlist")
    crk.add_argument("hash", nargs="+")
    crk.add_argument("-w", "--wordlist", required=True)
    crk.add_argument("-e", "--engine", default="auto", choices=["auto", "python", "hashcat"])
    crk.add_argument("-m", "--mode", type=int, default=None, help="force a hashcat mode")
    crk.add_argument("-r", "--rules", default=None, help="hashcat rule file")
    crk.set_defaults(func=cmd_crack)

    strs = sub.add_parser("strings", help="extract printable strings with offsets")
    strs.add_argument("file")
    strs.add_argument("-n", "--min-len", type=int, default=4)
    strs.add_argument("-l", "--limit", type=int, default=0)
    strs.set_defaults(func=cmd_strings)

    fil = sub.add_parser("file", help="file type and hashes")
    fil.add_argument("file")
    fil.set_defaults(func=cmd_file)

    pc = sub.add_parser("pcap", help="capture summary, optionally deauth analysis")
    pc.add_argument("file")
    pc.add_argument("--deauth", action="store_true", help="summarise deauth/disassoc frames")
    pc.set_defaults(func=cmd_pcap)

    wh = sub.add_parser("wifi-hash", help="extract a WPA handshake hash (hc22000)")
    wh.add_argument("file")
    wh.add_argument("-o", "--out", default=None)
    wh.set_defaults(func=cmd_wifi_hash)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\n[i] interrupted")
        return 130
    except BrokenPipeError:
        return 0
    except (ValueError, KeyError, OSError) as exc:
        # Bad input (empty key, one rail, invalid hex, unreadable file…) should be
        # a one-line error, never a traceback.
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
