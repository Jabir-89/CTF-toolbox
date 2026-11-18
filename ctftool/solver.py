"""Chain solver: try combinations of decoders/ciphers and rank the results.

The idea is the one thing a CTF player does by hand: base64 here, XOR there,
shift the letters, see if a flag falls out. This module automates the search.

Search strategy
---------------
1. Explore every chain of *structural* decoders (base64, base32, hex, URL,
   binary, rot13, reverse) up to ``max_depth``, de-duplicating results.
2. For each node, also try the expensive transforms as terminals: the 25
   Caesar shifts and all 256 single-byte XOR keys. When an XOR result looks
   like text, try Caesar on top of it (the common "xor then shift" combo).
3. Rank everything with the same English/flag scoring used by the brute-force
   commands, de-duplicate by output, return the best few with their chains.

This is a bounded search, not magic: long chains with many ciphers, or
transpositions, will not be found. It is fast enough to run interactively.
"""
from __future__ import annotations

import base64
import binascii
import time
import urllib.parse
from dataclasses import dataclass

from .ciphers import caesar, caesar_bruteforce, english_score, flag_bonus, xor_bytes

MAX_NODES = 250
MAX_SECONDS = 15.0


@dataclass(frozen=True)
class Candidate:
    chain: tuple[str, ...]
    data: bytes


def _b64(data: bytes) -> bytes | None:
    raw = b"".join(data.split())
    raw += b"=" * (-len(raw) % 4)
    try:
        return base64.b64decode(raw, validate=False)
    except (binascii.Error, ValueError):
        return None


def _b32(data: bytes) -> bytes | None:
    raw = b"".join(data.split()).upper()
    raw += b"=" * (-len(raw) % 8)
    try:
        return base64.b32decode(raw, casefold=True)
    except (binascii.Error, ValueError):
        return None


def _hex(data: bytes) -> bytes | None:
    raw = data.strip().replace(b"0x", b"").replace(b" ", b"").replace(b":", b"").replace(b"\n", b"")
    if not raw or len(raw) % 2:
        return None
    try:
        return bytes.fromhex(raw.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None


def _url(data: bytes) -> bytes | None:
    text = data.decode("latin-1")
    if "%" not in text:
        return None
    return urllib.parse.unquote_to_bytes(text)


def _binary(data: bytes) -> bytes | None:
    bits = "".join(ch for ch in data.decode("latin-1") if ch in "01")
    if not bits or len(bits) % 8:
        return None
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def _rot13(data: bytes) -> bytes | None:
    text = data.decode("latin-1")
    if not any(ch.isalpha() for ch in text):
        return None
    return caesar(text, 13).encode("latin-1")


def _reverse(data: bytes) -> bytes | None:
    return data[::-1]


DECODERS = [
    ("base64", _b64),
    ("base32", _b32),
    ("hex", _hex),
    ("url", _url),
    ("binary", _binary),
    ("rot13", _rot13),
    ("reverse", _reverse),
]


def as_text(data: bytes) -> str:
    return data.decode("latin-1", errors="replace")


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for ch in text if 32 <= ord(ch) < 127 or ch in "\r\n\t")
    return good / len(text)


def score_text(text: str) -> float:
    return english_score(text) + flag_bonus(text)


def _chain_label(chain: tuple[str, ...]) -> str:
    return " -> ".join(chain) if chain else "(input)"


def solve(data: bytes, max_depth: int = 3, top: int = 5,
          max_seconds: float = MAX_SECONDS) -> list[tuple[float, str, str]]:
    """Search decoder chains and return ``[(score, chain, text), ...]`` best first."""
    started = time.time()

    # Already a flag? Nothing to solve.
    input_text = as_text(data)
    if flag_bonus(input_text) > 0:
        return [(score_text(input_text), "(input)", input_text.strip())]

    nodes: list[Candidate] = [Candidate((), data)]
    seen: set[bytes] = {data}

    for _depth in range(max_depth):
        frontier: list[Candidate] = []
        for candidate in nodes:
            for name, decoder in DECODERS:
                try:
                    out = decoder(candidate.data)
                except (ValueError, UnicodeError, binascii.Error):
                    continue
                if not out or out == candidate.data or out in seen:
                    continue
                seen.add(out)
                frontier.append(Candidate(candidate.chain + (name,), out))
                if len(nodes) + len(frontier) >= MAX_NODES:
                    break
            if len(nodes) + len(frontier) >= MAX_NODES:
                break
        if not frontier:
            break
        nodes.extend(frontier)

    results: list[tuple[float, str, str]] = []

    def add(score: float, chain: tuple[str, ...], text: str) -> None:
        if not text.strip() or text == as_text(data):
            return
        results.append((score, _chain_label(chain), text))

    for candidate in nodes:
        if time.time() - started > max_seconds:
            break
        text = as_text(candidate.data)
        add(score_text(text), candidate.chain, text)

        # Caesar on the node itself (cheap, 25 shifts)
        if printable_ratio(text) > 0.8 and any(ch.isalpha() for ch in text):
            for shift, shifted, score in caesar_bruteforce(text):
                add(score, candidate.chain + (f"caesar {shift}",), shifted)

        # Single-byte XOR, and Caesar after XOR when the XOR result is readable
        for key in range(256):
            out = xor_bytes(candidate.data, bytes([key]))
            xor_text = as_text(out)
            xor_score = score_text(xor_text)
            chain = candidate.chain + (f"xor 0x{key:02x}",)
            add(xor_score, chain, xor_text)
            if printable_ratio(xor_text) > 0.85 and any(ch.isalpha() for ch in xor_text):
                for shift, shifted, score in caesar_bruteforce(xor_text):
                    add(score, chain + (f"caesar {shift}",), shifted)

    # Best first; prefer results that actually look like flags.
    results.sort(key=lambda item: (flag_bonus(item[2]), item[0]), reverse=True)

    out: list[tuple[float, str, str]] = []
    seen_text: set[str] = set()
    for score, chain, text in results:
        key = text.strip()
        if key in seen_text:
            continue
        seen_text.add(key)
        out.append((score, chain, text.strip()))
        if len(out) >= top:
            break
    return out
