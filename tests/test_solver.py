"""Tests for the chain solver."""
import unittest

from ctftool import ciphers, encodings, solver


class TestSolve(unittest.TestCase):
    def test_plain_flag_is_recognised(self):
        results = solver.solve(b"flag{already_here}")
        self.assertIn("flag{already_here}", results[0][2])

    def test_single_base64_layer(self):
        encoded = encodings.b64_encode("flag{hello_world}").encode()
        results = solver.solve(encoded)
        self.assertIn("flag{hello_world}", results[0][2])
        self.assertIn("base64", results[0][1])

    def test_hex_then_base64_then_caesar(self):
        payload = encodings.hex_encode(
            encodings.b64_encode(ciphers.caesar("flag{ch41n_w0rks}", 7))
        ).encode()
        results = solver.solve(payload, max_depth=3, top=3)
        self.assertIn("flag{ch41n_w0rks}", results[0][2])
        self.assertIn("caesar", results[0][1])

    def test_xor_then_caesar(self):
        payload = encodings.b64_encode(
            ciphers.xor_single(ciphers.caesar("flag{x0r_ch41n}", 5), 0x33)
        ).encode()
        results = solver.solve(payload, max_depth=2, top=5)
        found = any("flag{x0r_ch41n}" in text for _, _, text in results)
        self.assertTrue(found, f"flag not found in {results}")

    def test_garbage_does_not_crash(self):
        results = solver.solve(b"\x00\x01\x02\x03", max_depth=1, top=3)
        self.assertIsInstance(results, list)

    def test_results_are_ranked(self):
        encoded = encodings.b64_encode("the quick brown fox jumps over the lazy dog").encode()
        results = solver.solve(encoded, max_depth=2, top=3)
        scores = [score for score, _, _ in results]
        self.assertEqual(scores, sorted(scores, reverse=True))


class TestHelpers(unittest.TestCase):
    def test_printable_ratio(self):
        self.assertEqual(solver.printable_ratio("abc"), 1.0)
        self.assertLess(solver.printable_ratio("\x00\x01"), 0.5)

    def test_decoders_reject_bad_input(self):
        self.assertIsNone(solver._hex(b"zz"))
        self.assertIsNone(solver._binary(b"0123"))
        self.assertIsNone(solver._url(b"no-escapes"))

    def test_rot13_roundtrip(self):
        out = solver._rot13(b"Hello")
        self.assertEqual(out, b"Uryyb")


if __name__ == "__main__":
    unittest.main()
