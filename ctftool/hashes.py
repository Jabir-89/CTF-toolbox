"""Hash identification and small-scale cracking helpers.

Identification works on the hex digest alone. Cracking here is intentionally
CPU-bounded: use it for CTF flags and lab passwords, not for real hashes.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

# (name, regex, hashcat mode, python hashlib name or None)
SIGNATURES = [
    ("bcrypt", re.compile(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$"), 3200, None),
    ("sha512crypt", re.compile(r"^\$6\$[^\s]{1,16}\$[./A-Za-z0-9]{86}$"), 1800, None),
    ("sha256crypt", re.compile(r"^\$5\$[^\s]{1,16}\$[./A-Za-z0-9]{43}$"), 7400, None),
    ("md5crypt", re.compile(r"^\$1\$[^\s]{1,8}\$[./A-Za-z0-9]{22}$"), 500, None),
    ("mysql4.1+", re.compile(r"^\*[0-9A-F]{40}$"), 300, None),
    ("md5", re.compile(r"^[a-f0-9]{32}$", re.I), 0, "md5"),
    ("ntlm", re.compile(r"^[a-f0-9]{32}$", re.I), 1000, None),
    ("sha1", re.compile(r"^[a-f0-9]{40}$", re.I), 100, "sha1"),
    ("sha224", re.compile(r"^[a-f0-9]{56}$", re.I), 1300, "sha224"),
    ("sha256", re.compile(r"^[a-f0-9]{64}$", re.I), 1400, "sha256"),
    ("sha384", re.compile(r"^[a-f0-9]{96}$", re.I), 10800, "sha384"),
    ("sha512", re.compile(r"^[a-f0-9]{128}$", re.I), 1700, "sha512"),
]

PYTHON_HASHES = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}


def identify(digest: str) -> list[tuple[str, int]]:
    """Return ``[(name, hashcat_mode), ...]`` for every signature that matches."""
    digest = digest.strip()
    return [(name, mode) for name, pattern, mode, _ in SIGNATURES if pattern.match(digest)]


def _python_algo(digest: str) -> str | None:
    """Pick a hashlib algorithm for a plain hex digest."""
    if not re.fullmatch(r"[a-f0-9]+", digest.strip(), re.I):
        return None
    lengths = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}
    return lengths.get(len(digest.strip()))


def crack_python(digest: str, wordlist: Path, max_candidates: int = 5_000_000) -> str | None:
    """Compare against a wordlist using hashlib. Returns the plaintext or None."""
    digest = digest.strip().lower()
    algo = _python_algo(digest)
    if algo is None:
        return None
    if not wordlist.is_file():
        raise FileNotFoundError(f"wordlist not found: {wordlist}")

    with wordlist.open("rb") as fh:
        for i, line in enumerate(fh):
            if i >= max_candidates:
                break
            candidate = line.rstrip(b"\r\n")
            if hashlib.new(algo, candidate).hexdigest() == digest:
                return candidate.decode("utf-8", errors="replace")
    return None


def hashcat_available() -> bool:
    return shutil.which("hashcat") is not None


def hashcat_command(digest: str, wordlist: Path, mode: int | None = None,
                    rules: str | None = None, session: str = "ctftool") -> list[str]:
    """Build (do not run) a hashcat command for a single digest."""
    if mode is None:
        guesses = identify(digest)
        mode = guesses[0][1] if guesses else 0
    cmd = [
        "hashcat", "-m", str(mode), "-a", "0", digest.strip(), str(wordlist),
        "--potfile-path", "ctftool.pot", "--session", session, "--status",
    ]
    if rules:
        cmd += ["-r", rules]
    return cmd


def hashcat_crack(digest: str, wordlist: Path, mode: int | None = None,
                  rules: str | None = None) -> str | None:
    """Run hashcat --show afterwards and return the plaintext, if any."""
    if not hashcat_available():
        raise RuntimeError("hashcat not installed")
    cmd = hashcat_command(digest, wordlist, mode, rules)
    subprocess.run(cmd, check=False, capture_output=True, text=True)
    show = subprocess.run(
        ["hashcat", "-m", str(mode if mode is not None else 0), digest.strip(), "--show",
         "--potfile-path", "ctftool.pot", "--quiet"],
        check=False, capture_output=True, text=True,
    )
    for line in show.stdout.splitlines():
        _, sep, plain = line.rpartition(":")
        if sep and plain:
            return plain
    return None
