import unittest

from ctftool import encodings


class TestBase64(unittest.TestCase):
    def test_roundtrip(self):
        for text in ["hello", "flag{test_123}", "مرحبا", ""]:
            self.assertEqual(encodings.b64_decode(encodings.b64_encode(text)), text)

    def test_known_value(self):
        self.assertEqual(encodings.b64_encode("hello"), "aGVsbG8=")
        self.assertEqual(encodings.b64_decode("aGVsbG8="), "hello")

    def test_missing_padding(self):
        self.assertEqual(encodings.b64_decode("aGVsbG8"), "hello")

    def test_whitespace_tolerated(self):
        self.assertEqual(encodings.b64_decode("aGVs\nbG8="), "hello")


class TestHexAndBinary(unittest.TestCase):
    def test_hex(self):
        self.assertEqual(encodings.hex_encode("hi"), "6869")
        self.assertEqual(encodings.hex_decode("6869"), "hi")

    def test_hex_with_separators(self):
        self.assertEqual(encodings.hex_decode("68:69"), "hi")
        self.assertEqual(encodings.hex_decode("0x6869"), "hi")

    def test_hex_odd_length_rejected(self):
        # Silently padding corrupts the data; fail loudly instead.
        with self.assertRaises(ValueError):
            encodings.hex_decode("686")

    def test_hex_invalid(self):
        with self.assertRaises(ValueError):
            encodings.hex_decode("zzzz")

    def test_binary(self):
        self.assertEqual(encodings.binary_encode("A"), "01000001")
        self.assertEqual(encodings.binary_decode("01000001"), "A")

    def test_binary_bad_length(self):
        with self.assertRaises(ValueError):
            encodings.binary_decode("0100")


class TestMisc(unittest.TestCase):
    def test_url(self):
        self.assertEqual(encodings.url_decode(encodings.url_encode("a b&c")), "a b&c")

    def test_rot13_involutive(self):
        self.assertEqual(encodings.rot13(encodings.rot13("Hello")), "Hello")

    def test_morse_roundtrip(self):
        code = encodings.morse_encode("SOS")
        self.assertEqual(code, "... --- ...")
        self.assertEqual(encodings.morse_decode(code), "SOS")

    def test_reverse(self):
        self.assertEqual(encodings.reverse("abc"), "cba")


class TestAutoDecode(unittest.TestCase):
    def test_finds_base64(self):
        results = dict(encodings.auto_decode("ZmxhZ3toZWxsb30="))
        self.assertIn("base64", results)
        self.assertEqual(results["base64"], "flag{hello}")

    def test_finds_hex(self):
        names = [name for name, _ in encodings.auto_decode("666c6167")]
        self.assertIn("hex", names)

    def test_garbage_returns_nothing(self):
        self.assertEqual(encodings.auto_decode("\x00\x01\x02"), [])


class TestReadable(unittest.TestCase):
    def test_ascii(self):
        self.assertTrue(encodings.is_readable("hello world"))

    def test_binary_noise(self):
        self.assertFalse(encodings.is_readable("\x00\x01\x02\x03"))


if __name__ == "__main__":
    unittest.main()
