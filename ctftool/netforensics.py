"""Network capture helpers: pcap summary, deauth analysis, WPA hash extraction.

Everything reads files you already have. Nothing here transmits.
"""
from __future__ import annotations

import struct
import shutil
import subprocess
from collections import Counter
from pathlib import Path

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", "microsecond"),
    b"\xa1\xb2\xc3\xd4": (">", "microsecond"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanosecond"),
    b"\xa1\xb2\x3c\x4d": (">", "nanosecond"),
}

LINK_TYPES = {
    1: "Ethernet",
    105: "IEEE 802.11",
    127: "802.11 + radiotap",
    113: "Linux cooked (SLL)",
    276: "Linux cooked v2",
    0: "BSD loopback",
}


def pcap_summary(path: Path) -> dict[str, object]:
    """Parse a classic pcap without external tools.

    Returns packet count, byte total, link type and capture duration.
    Raises ``ValueError`` for pcapng or malformed files.
    """
    raw = path.read_bytes()
    if len(raw) < 24:
        raise ValueError("file too small to be a pcap")
    if raw[:4] == b"\x0a\x0d\x0d\x0a":
        raise ValueError("pcapng detected — use tshark -r <file> -q -z io,stat,0")

    magic = raw[:4]
    if magic not in PCAP_MAGIC:
        raise ValueError("not a pcap file (bad magic)")
    endian, resolution = PCAP_MAGIC[magic]

    major, minor, _tz, _sig, snaplen, network = struct.unpack(endian + "HHiIII", raw[4:24])
    offset = 24
    count = 0
    first_ts = last_ts = None
    total_bytes = 0

    while offset + 16 <= len(raw):
        ts_sec, ts_frac, incl, orig = struct.unpack(endian + "IIII", raw[offset:offset + 16])
        if offset + 16 + incl > len(raw):
            break  # truncated capture: stop instead of reading past the end
        offset += 16 + incl
        ts = ts_sec + (ts_frac / 1e9 if resolution == "nanosecond" else ts_frac / 1e6)
        first_ts = ts if first_ts is None else min(first_ts, ts)
        last_ts = ts if last_ts is None else max(last_ts, ts)
        total_bytes += orig
        count += 1

    return {
        "packets": count,
        "bytes": total_bytes,
        "link_type": LINK_TYPES.get(network, f"unknown ({network})"),
        "version": f"{major}.{minor}",
        "duration_s": round((last_ts - first_ts), 3) if first_ts is not None else 0.0,
        "snaplen": snaplen,
    }


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def deauth_frames(path: Path) -> dict[str, object] | None:
    """Summarise deauth (0x0c) and disassoc (0x0a) management frames via tshark.

    Returns None when tshark is not installed. This is analysis of a capture,
    not an attack: it never sends a frame.
    """
    if not tshark_available():
        return None
    cmd = [
        "tshark", "-r", str(path), "-Y",
        "wlan.fc.type_subtype==0x0c || wlan.fc.type_subtype==0x0a",
        "-T", "fields", "-e", "wlan.fc.type_subtype", "-e", "wlan.sa",
        "-e", "wlan.da", "-e", "wlan.bssid", "-e", "wlan.fixed.reason_code",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError(proc.stderr.strip() or "tshark failed")

    by_source: Counter[str] = Counter()
    by_reason: Counter[str] = Counter()
    total = 0
    for line in proc.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) < 5 or not fields[0]:
            continue
        total += 1
        by_source[fields[1] or fields[3] or "unknown"] += 1
        by_reason[fields[4] or "unknown"] += 1

    return {
        "total": total,
        "by_source": by_source.most_common(10),
        "by_reason": by_reason.most_common(10),
    }


def wpa_hash(path: Path, out: Path | None = None) -> Path | None:
    """Convert a capture to hashcat's 22000 format with hcxpcapngtool.

    Returns the output path, or None when no handshake/PMKID was present.
    """
    if not shutil.which("hcxpcapngtool"):
        raise RuntimeError("hcxpcapngtool not installed: sudo apt install hcxtools")
    target = out or path.with_suffix(".hc22000")
    subprocess.run(["hcxpcapngtool", "-o", str(target), str(path)],
                   capture_output=True, text=True, check=False)
    if target.exists() and target.stat().st_size > 0:
        return target
    return None
