"""CLI-level tests: bad input must produce a message and an exit code, never a
traceback. Run with a captured stderr so the checks are about behaviour only.
"""
import hashlib
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ctftool.cli import main
from helpers import scratch


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestBadInputIsGraceful(unittest.TestCase):
    def test_vigenere_empty_key(self):
        code, _, err = run("vigenere", "abc", "-k", "123")
        self.assertEqual(code, 2)
        self.assertIn("key must contain", err)
        self.assertNotIn("Traceback", err)

    def test_railfence_one_rail(self):
        code, _, err = run("railfence", "abc", "-r", "1")
        self.assertEqual(code, 2)
        self.assertIn("rails must be", err)

    def test_xor_key_out_of_range(self):
        code, _, err = run("xor", "abc", "-k", "999")
        self.assertEqual(code, 2)
        self.assertIn("key must be", err)

    def test_invalid_hex(self):
        code, _, err = run("decode", "-f", "hex", "zzzz")
        self.assertEqual(code, 2)
        self.assertIn("hex", err.lower())

    def test_missing_file(self):
        code, _, err = run("file", "/nope/does-not-exist.bin")
        self.assertEqual(code, 2)
        self.assertIn("not a file", err)


class TestCrackEngineSelection(unittest.TestCase):
    def test_unsupported_hash_length_is_explained(self):
        with scratch() as tmp:
            wordlist = tmp / "words.txt"
            wordlist.write_text("alpha\nbeta\n")
            code, _, err = run("crack", "deadbeef", "-w", str(wordlist), "-e", "python")
        self.assertEqual(code, 2)
        self.assertIn("md5/sha1/sha2", err)

    def test_crack_finds_md5(self):
        with scratch() as tmp:
            wordlist = tmp / "words.txt"
            wordlist.write_text("alpha\nhunter2\n")
            digest = hashlib.md5(b"hunter2").hexdigest()
            code, out, _ = run("crack", digest, "-w", str(wordlist), "-e", "python")
        self.assertEqual(code, 0)
        self.assertIn("hunter2", out)


class TestExitCodes(unittest.TestCase):
    def test_ok_is_zero(self):
        code, out, _ = run("encode", "-f", "base64", "hi")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "aGk=")

    def test_hashid_unknown_is_one(self):
        code, _, _ = run("hashid", "not-a-hash")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
