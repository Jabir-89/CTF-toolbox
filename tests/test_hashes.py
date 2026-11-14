import hashlib
import unittest
from pathlib import Path

from ctftool import hashes
from helpers import scratch


class TestIdentify(unittest.TestCase):
    def test_md5(self):
        names = [n for n, _ in hashes.identify("5d41402abc4b2a76b9719d911017c592")]
        self.assertIn("md5", names)

    def test_sha256(self):
        digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        names = [n for n, _ in hashes.identify(digest)]
        self.assertIn("sha256", names)

    def test_bcrypt(self):
        digest = "$2b$12$" + "a" * 53
        names = [n for n, _ in hashes.identify(digest)]
        self.assertIn("bcrypt", names)

    def test_unknown(self):
        self.assertEqual(hashes.identify("not-a-hash"), [])

    def test_mode_numbers(self):
        self.assertEqual(hashes.identify("5d41402abc4b2a76b9719d911017c592")[0][1], 0)


class TestCrackPython(unittest.TestCase):
    def test_finds_md5(self):
        with scratch() as d:
            wordlist = d / "words.txt"
            wordlist.write_text("nope\nhunter2\nsecret\n")
            digest = hashlib.md5(b"hunter2").hexdigest()
            self.assertEqual(hashes.crack_python(digest, wordlist), "hunter2")

    def test_finds_sha256(self):
        with scratch() as d:
            wordlist = d / "words.txt"
            wordlist.write_text("nope\nhunter2\nsecret\n")
            digest = hashlib.sha256(b"secret").hexdigest()
            self.assertEqual(hashes.crack_python(digest, wordlist), "secret")

    def test_missing_returns_none(self):
        with scratch() as d:
            wordlist = d / "words.txt"
            wordlist.write_text("nope\nhunter2\n")
            digest = hashlib.sha1(b"absent").hexdigest()
            self.assertIsNone(hashes.crack_python(digest, wordlist))

    def test_unsupported_length(self):
        with scratch() as d:
            wordlist = d / "words.txt"
            wordlist.write_text("abc\n")
            self.assertIsNone(hashes.crack_python("abcd", wordlist))

    def test_missing_wordlist(self):
        with scratch() as d:
            with self.assertRaises(FileNotFoundError):
                hashes.crack_python("5d41402abc4b2a76b9719d911017c592", d / "absent.txt")


class TestHashcatCommand(unittest.TestCase):
    def test_builds_command(self):
        cmd = hashes.hashcat_command("5d41402abc4b2a76b9719d911017c592", Path("rockyou.txt"))
        self.assertEqual(cmd[0], "hashcat")
        self.assertEqual(cmd[cmd.index("-m") + 1], "0")

    def test_explicit_mode(self):
        cmd = hashes.hashcat_command("x", Path("w.txt"), mode=22000)
        self.assertEqual(cmd[cmd.index("-m") + 1], "22000")

    def test_rules_appended(self):
        cmd = hashes.hashcat_command("x", Path("w.txt"), mode=0, rules="best64.rule")
        self.assertEqual(cmd[cmd.index("-r") + 1], "best64.rule")


if __name__ == "__main__":
    unittest.main()
