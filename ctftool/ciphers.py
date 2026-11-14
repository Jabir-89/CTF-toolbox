"""Classical ciphers with brute-force helpers.

All functions are pure: no I/O, no randomness.
"""
from __future__ import annotations

import math

# Relative letter frequencies in English, plus space as the most common symbol.
LETTER_FREQ = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702,
    "f": 2.228, "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153,
    "k": 0.772, "l": 4.025, "m": 2.406, "n": 6.749, "o": 7.507,
    "p": 1.929, "q": 0.095, "r": 5.987, "s": 6.327, "t": 9.056,
    "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150, "y": 1.974,
    "z": 0.074,
}
SPACE_PROB = 0.18
LETTER_PROB = {ch: freq / 100.0 for ch, freq in LETTER_FREQ.items()}
OTHER_PROB = 0.002

# Bigrams that show up constantly in English, and ones that essentially never do.
# Short candidate texts (CTF flags, sentences) need this: letter frequencies alone
# are not decisive on 20-40 characters.
COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es",
    "or", "te", "of", "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng",
    "se", "ha", "as", "ou", "io", "le", "ve", "co", "me", "de", "hi", "ri",
    "ro", "ic", "ne", "ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si",
    "om", "ur", "ca", "el", "ta", "it", "no", "us", "so", "ot", "il", "ac",
}
RARE_BIGRAMS = {
    "zx", "qz", "xq", "jz", "vq", "qx", "kq", "qk", "jq", "qj", "wx", "xw",
    "fq", "qf", "vx", "xv", "jv", "vj", "gq", "qg", "hq", "qh", "zq", "qy",
}

# CTF flags are not English: `flag{ch41n_w0rks}` scores badly against letter
# frequencies, so every Caesar shift of it looks equally wrong. A known flag
# prefix is a much stronger signal than English-ness.
FLAG_PREFIXES = ("flag{", "ctf{", "htb{", "picoctf{", "thm{", "ictf{")
FLAG_BONUS = 3.0


def flag_bonus(text: str) -> float:
    """Bonus when the candidate looks like a CTF flag. 0.0 otherwise."""
    lowered = text.lower()
    return FLAG_BONUS if any(prefix in lowered for prefix in FLAG_PREFIXES) else 0.0


def english_score(text: str) -> float:
    """Higher is more English-like.

    Average log-probability per character (letters + spaces, everything else
    rare) plus a bonus for common bigrams. Roughly -1.7 (perfect English) to
    -6 (noise); compare candidates of the same length.
    """
    if not text:
        return float("-inf")
    text = text.lower()
    total = 0.0
    for ch in text:
        if ch == " ":
            total += math.log(SPACE_PROB)
        elif ch in LETTER_PROB:
            total += math.log(LETTER_PROB[ch])
        else:
            total += math.log(OTHER_PROB)
    base = total / len(text)

    words = "".join(ch if ch.isalpha() or ch == " " else " " for ch in text)
    pairs = len(words) - 1
    if pairs < 1:
        return base
    hits = sum(1 for i in range(pairs) if words[i:i + 2] in COMMON_BIGRAMS)
    misses = sum(1 for i in range(pairs) if words[i:i + 2] in RARE_BIGRAMS)
    return base + 1.5 * (hits / pairs) - 1.5 * (misses / pairs) + flag_bonus(text)


# ---------------------------------------------------------------- caesar

def caesar(text: str, shift: int) -> str:
    """Shift every letter by ``shift`` positions (negative = decrypt)."""
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def caesar_bruteforce(text: str) -> list[tuple[int, str, float]]:
    """All 25 shifts, best English score first."""
    candidates = [(shift, caesar(text, shift), english_score(caesar(text, shift)))
                  for shift in range(1, 26)]
    return sorted(candidates, key=lambda item: item[2], reverse=True)


# ---------------------------------------------------------------- atbash

def atbash(text: str) -> str:
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr(base + (25 - (ord(ch) - base))))
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------- vigenere

def _clean_key(key: str) -> str:
    key = "".join(ch for ch in key.upper() if ch.isalpha())
    if not key:
        raise ValueError("key must contain at least one letter")
    return key


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    key = _clean_key(key)
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = ord(key[ki % len(key)]) - ord("A")
            if decrypt:
                shift = -shift
            out.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------- rail fence

def railfence_encode(text: str, rails: int = 3) -> str:
    if rails < 2:
        raise ValueError("rails must be >= 2")
    rows: list[list[str]] = [[] for _ in range(rails)]
    rail, step = 0, 1
    for ch in text:
        rows[rail].append(ch)
        if rail == 0:
            step = 1
        elif rail == rails - 1:
            step = -1
        rail += step
    return "".join("".join(row) for row in rows)


def railfence_decode(text: str, rails: int = 3) -> str:
    if rails < 2:
        raise ValueError("rails must be >= 2")
    pattern = []
    rail, step = 0, 1
    for _ in text:
        pattern.append(rail)
        if rail == 0:
            step = 1
        elif rail == rails - 1:
            step = -1
        rail += step

    counts = [pattern.count(r) for r in range(rails)]
    chunks, idx = [], 0
    for count in counts:
        chunks.append(list(text[idx:idx + count]))
        idx += count

    cursors = [0] * rails
    out = []
    for r in pattern:
        out.append(chunks[r][cursors[r]])
        cursors[r] += 1
    return "".join(out)


# ---------------------------------------------------------------- xor

def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_single(text: str, key: int) -> str:
    if not 0 <= key <= 255:
        raise ValueError("key must be 0-255")
    return xor_bytes(text.encode(), bytes([key])).decode("latin-1")


def xor_bruteforce(text: str, limit: int = 10) -> list[tuple[int, str, float]]:
    """Try every single-byte key, best English score first."""
    raw = text.encode("latin-1", errors="replace")
    scored = []
    for key in range(256):
        guess = xor_bytes(raw, bytes([key])).decode("latin-1")
        scored.append((key, guess, english_score(guess)))
    scored.sort(key=lambda item: item[2], reverse=True)
    return scored[:limit]
