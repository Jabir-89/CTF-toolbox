import hashlib
import struct
import unittest
from pathlib import Path

from ctftool import files, netforensics
from helpers import scratch


def make_pcap(path: Path, packets: int = 2) -> None:
    """Write a minimal classic pcap with N dummy 802.11 packets."""
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105)
    body = b""
    for i in range(packets):
        payload = b"\x00" * 24
        body += struct.pack("<IIII", 1700000000 + i, 0, len(payload), len(payload)) + payload
    path.write_bytes(header + body)


class TestSniff(unittest.TestCase):
    def test_png(self):
        with scratch() as d:
            f = d / "a.bin"
            f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
            self.assertEqual(files.sniff(f), "PNG image")

    def test_zip(self):
        with scratch() as d:
            f = d / "a.bin"
            f.write_bytes(b"PK\x03\x04" + b"\x00" * 32)
            self.assertIn("ZIP", files.sniff(f))

    def test_text(self):
        with scratch() as d:
            f = d / "a.txt"
            f.write_text("hello world\n" * 10)
            self.assertEqual(files.sniff(f), "text")


class TestStrings(unittest.TestCase):
    def test_finds_strings_with_offsets(self):
        with scratch() as d:
            f = d / "blob.bin"
            f.write_bytes(b"\x00\x01hello\x00flag{abc}\x00")
            texts = [t for _, t in files.strings(f, min_len=4)]
            self.assertIn("hello", texts)
            self.assertIn("flag{abc}", texts)

    def test_offsets_are_correct(self):
        with scratch() as d:
            f = d / "blob.bin"
            f.write_bytes(b"\x00\x00\x00hi there\x00")
            hits = files.strings(f, min_len=2)
            self.assertEqual(hits[0][0], 3)
            self.assertEqual(hits[0][1], "hi there")

    def test_min_len_filters(self):
        with scratch() as d:
            f = d / "b.bin"
            f.write_bytes(b"ab\x00cd\x00")
            self.assertEqual(len(files.strings(f, min_len=3)), 0)

    def test_limit(self):
        with scratch() as d:
            f = d / "c.bin"
            f.write_bytes(b"aaaa\x00bbbb\x00cccc\x00")
            self.assertEqual(len(files.strings(f, min_len=2, limit=2)), 2)

    def test_min_len_validation(self):
        with scratch() as d:
            f = d / "d.bin"
            f.write_bytes(b"abc\x00")
            with self.assertRaises(ValueError):
                files.strings(f, min_len=0)


class TestInfo(unittest.TestCase):
    def test_digests_match_hashlib(self):
        with scratch() as d:
            f = d / "x.txt"
            f.write_bytes(b"hello")
            data = files.info(f)
            self.assertEqual(data["md5"], hashlib.md5(b"hello").hexdigest())
            self.assertEqual(data["sha256"], hashlib.sha256(b"hello").hexdigest())
            self.assertEqual(data["size"], 5)


class TestPcap(unittest.TestCase):
    def test_summary(self):
        with scratch() as d:
            f = d / "x.pcap"
            make_pcap(f, packets=3)
            summary = netforensics.pcap_summary(f)
            self.assertEqual(summary["packets"], 3)
            self.assertEqual(summary["link_type"], "IEEE 802.11")
            self.assertEqual(summary["version"], "2.4")

    def test_not_pcap(self):
        with scratch() as d:
            f = d / "x.bin"
            f.write_bytes(b"just some text, definitely not a capture file at all")
            with self.assertRaises(ValueError):
                netforensics.pcap_summary(f)

    def test_too_small(self):
        with scratch() as d:
            f = d / "x.bin"
            f.write_bytes(b"\x00")
            with self.assertRaises(ValueError):
                netforensics.pcap_summary(f)

    def test_pcapng_rejected(self):
        with scratch() as d:
            f = d / "x.pcapng"
            f.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
            with self.assertRaises(ValueError):
                netforensics.pcap_summary(f)


if __name__ == "__main__":
    unittest.main()
