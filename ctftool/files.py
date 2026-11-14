"""File forensics helpers: hashes, magic bytes, printable strings.

Read-only. Nothing is written or executed.
"""
from __future__ import annotations

import hashlib
import string
from pathlib import Path

MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP archive (or docx/xlsx/apk/jar)"),
    (b"\x1f\x8b", "gzip archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE / DOS executable"),
    (b"\xd0\xcf\x11\xe0", "OLE2 (legacy doc/xls)"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"\xd4\xc3\xb2\xa1", "pcap capture (little endian)"),
    (b"\xa1\xb2\xc3\xd4", "pcap capture (big endian)"),
    (b"\x0a\x0d\x0d\x0a", "pcapng capture"),
    (b"RIFF", "RIFF container (wav/avi/webp)"),
    (b"\x00\x00\x01\x00", "ICO icon"),
    (b"ID3", "MP3 with ID3 tag"),
    (b"OggS", "Ogg container"),
    (b"BM", "BMP image"),
    (b"-----BEGIN", "PEM / certificate or key"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class"),
]


def sniff(path: Path, size: int = 64) -> str:
    """Best-effort file type from the first bytes (no external tools)."""
    with path.open("rb") as fh:
        head = fh.read(size)
    for magic, name in MAGIC:
        if head.startswith(magic) or magic in head[:32]:
            return name
    text = head.decode("utf-8", errors="replace")
    printable = sum(1 for ch in text if ch in string.printable)
    if head and printable / len(head) > 0.9:
        return "text"
    return "unknown binary"


def digests(path: Path) -> dict[str, str]:
    """MD5, SHA1 and SHA256 of a file, streamed (safe for large files)."""
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def info(path: Path) -> dict[str, object]:
    stat = path.stat()
    data = digests(path)
    return {
        "path": str(path),
        "size": stat.st_size,
        "type": sniff(path),
        **data,
    }


def strings(path: Path, min_len: int = 4, limit: int = 0) -> list[tuple[int, str]]:
    """Printable ASCII runs of at least ``min_len``, with byte offsets.

    ``limit`` caps how many results are returned (0 = no cap).
    """
    if min_len < 1:
        raise ValueError("min_len must be >= 1")
    printable = set(string.printable) - {"\r", "\n", "\t", "\x0b", "\x0c"}
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 0
    with path.open("rb") as fh:
        offset = 0
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            for byte in chunk:
                ch = chr(byte)
                if ch in printable:
                    if not buf:
                        start = offset
                    buf.append(ch)
                else:
                    if len(buf) >= min_len:
                        out.append((start, "".join(buf)))
                        if limit and len(out) >= limit:
                            return out
                    buf = []
                offset += 1
    if len(buf) >= min_len:
        out.append((start, "".join(buf)))
    return out
