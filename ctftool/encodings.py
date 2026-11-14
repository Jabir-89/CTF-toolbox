"""Encoders and decoders for CTF "misc" challenges.

Every function takes plain ``str`` and returns ``str`` unless noted.
Nothing here touches the network or the filesystem.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import urllib.parse

MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
    "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
    "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
    "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
    "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
    "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.",
    "!": "-.-.--", "/": "-..-.", "(": "-.--.", ")": "-.--.-",
    "&": ".-...", ":": "---...", ";": "-.-.-.", "=": "-...-",
    "+": ".-.-.", "-": "-....-", "_": "..--.-", '"': ".-..-.",
    "$": "...-..-", "@": ".--.-.",
}
MORSE_REVERSE = {v: k for k, v in MORSE.items()}


def to_bytes(text: str) -> bytes:
    return text.encode("utf-8", errors="surrogatepass")


# ---------------------------------------------------------------- base64

def b64_encode(text: str) -> str:
    return base64.b64encode(to_bytes(text)).decode("ascii")


def b64_decode(text: str) -> str:
    raw = "".join(text.split())
    raw += "=" * (-len(raw) % 4)
    return base64.b64decode(raw, validate=False).decode("utf-8", errors="replace")


# ---------------------------------------------------------------- base32

def b32_encode(text: str) -> str:
    return base64.b32encode(to_bytes(text)).decode("ascii")


def b32_decode(text: str) -> str:
    raw = "".join(text.split()).upper()
    raw += "=" * (-len(raw) % 8)
    return base64.b32decode(raw, casefold=True).decode("utf-8", errors="replace")


# ---------------------------------------------------------------- hex

def hex_encode(text: str) -> str:
    return to_bytes(text).hex()


def hex_decode(text: str) -> str:
    raw = text.strip().replace("0x", "").replace(" ", "").replace(":", "").replace("\n", "")
    if len(raw) % 2:
        raise ValueError(f"odd number of hex digits ({len(raw)}) — expected pairs")
    try:
        return bytes.fromhex(raw).decode("utf-8", errors="replace")
    except ValueError as exc:
        raise ValueError(f"not valid hex: {exc}") from exc


# ---------------------------------------------------------------- binary

def binary_encode(text: str, sep: str = " ") -> str:
    return sep.join(f"{b:08b}" for b in to_bytes(text))


def binary_decode(text: str) -> str:
    bits = "".join(ch for ch in text if ch in "01")
    if len(bits) % 8:
        raise ValueError("bit count is not a multiple of 8")
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)).decode(
        "utf-8", errors="replace"
    )


# ---------------------------------------------------------------- url

def url_encode(text: str) -> str:
    return urllib.parse.quote(text, safe="")


def url_decode(text: str) -> str:
    return urllib.parse.unquote(text)


# ---------------------------------------------------------------- morse

def morse_encode(text: str) -> str:
    words = []
    for word in text.upper().split():
        codes = [MORSE[ch] for ch in word if ch in MORSE]
        if codes:
            words.append(" ".join(codes))
    return " / ".join(words)


def morse_decode(text: str) -> str:
    out = []
    for word in text.strip().split("/"):
        letters = []
        for code in word.split():
            letters.append(MORSE_REVERSE.get(code, "?"))
        out.append("".join(letters))
    return " ".join(out)


# ---------------------------------------------------------------- misc

def rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def reverse(text: str) -> str:
    return text[::-1]


# ---------------------------------------------------------------- auto

def is_readable(text: str, threshold: float = 0.85) -> bool:
    """True when most characters are printable ASCII or common whitespace."""
    if not text:
        return False
    good = sum(1 for ch in text if 32 <= ord(ch) < 127 or ch in "\r\n\t")
    return good / len(text) >= threshold


DECODERS = [
    ("base64", b64_decode),
    ("base32", b32_decode),
    ("hex", hex_decode),
    ("url", url_decode),
    ("binary", binary_decode),
    ("morse", morse_decode),
    ("rot13", rot13),
    ("reverse", reverse),
]


STRUCTURAL = {"base64", "base32", "hex", "url", "binary", "morse"}


def auto_decode(text: str, min_len: int = 2) -> list[tuple[str, str]]:
    """Try every decoder, keep the results that look like readable text.

    Returns a list of ``(decoder_name, result)``, de-duplicated on result. When a
    structural decoder (base64/hex/…) succeeds, the lossy transforms (rot13,
    reverse) are dropped as noise — they only show up when nothing else matched.
    """
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, fn in DECODERS:
        try:
            out = fn(text)
        except (ValueError, binascii.Error, UnicodeError):
            continue
        if out and out != text and len(out.strip()) >= min_len and is_readable(out):
            if out not in seen:
                seen.add(out)
                results.append((name, out))
    if any(name in STRUCTURAL for name, _ in results):
        results = [(n, v) for n, v in results if n in STRUCTURAL]
    return results


ENCODERS = {
    "base64": b64_encode,
    "base32": b32_encode,
    "hex": hex_encode,
    "binary": binary_encode,
    "url": url_encode,
    "morse": morse_encode,
    "rot13": rot13,
    "reverse": reverse,
}

DECODER_MAP = dict(DECODERS)
