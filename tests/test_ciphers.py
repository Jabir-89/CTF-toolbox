import unittest

from ctftool import ciphers


class TestCaesar(unittest.TestCase):
    def test_known_shift(self):
        self.assertEqual(ciphers.caesar("abc", 3), "def")
        self.assertEqual(ciphers.caesar("def", -3), "abc")

    def test_preserves_case_and_symbols(self):
        self.assertEqual(ciphers.caesar("Abc-Xyz!", 1), "Bcd-Yza!")

    def test_bruteforce_puts_real_shift_first(self):
        plain = "the quick brown fox jumps over the lazy dog"
        cipher = ciphers.caesar(plain, 7)
        shift, best, _ = ciphers.caesar_bruteforce(cipher)[0]
        self.assertEqual(best, plain)
        self.assertEqual(shift, 19)  # decrypt shift

    def test_all_shifts_returned(self):
        self.assertEqual(len(ciphers.caesar_bruteforce("abc")), 25)


class TestAtbash(unittest.TestCase):
    def test_involutive(self):
        self.assertEqual(ciphers.atbash(ciphers.atbash("Hello World")), "Hello World")

    def test_known(self):
        self.assertEqual(ciphers.atbash("abc"), "zyx")


class TestVigenere(unittest.TestCase):
    def test_wikipedia_vector(self):
        # ATTACKATDAWN with key LEMON -> LXFOPVEFRNHR
        self.assertEqual(ciphers.vigenere("ATTACKATDAWN", "LEMON"), "LXFOPVEFRNHR")
        self.assertEqual(ciphers.vigenere("LXFOPVEFRNHR", "LEMON", decrypt=True), "ATTACKATDAWN")

    def test_case_preserved(self):
        cipher = ciphers.vigenere("AttackAtDawn", "lemon")
        self.assertEqual(ciphers.vigenere(cipher, "LEMON", decrypt=True), "AttackAtDawn")

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            ciphers.vigenere("abc", "123")

    def test_spaces_do_not_advance_key(self):
        self.assertEqual(
            ciphers.vigenere(ciphers.vigenere("ab cd", "key"), "key", decrypt=True),
            "ab cd",
        )


class TestRailFence(unittest.TestCase):
    def test_roundtrip(self):
        plain = "WEAREDISCOVEREDFLEEATONCE"
        for rails in (2, 3, 5):
            self.assertEqual(ciphers.railfence_decode(ciphers.railfence_encode(plain, rails), rails), plain)

    def test_known_three_rails(self):
        self.assertEqual(ciphers.railfence_encode("WEAREDISCOVEREDFLEEATONCE", 3),
                         "WECRLTEERDSOEEFEAOCAIVDEN")

    def test_too_few_rails(self):
        with self.assertRaises(ValueError):
            ciphers.railfence_encode("abc", 1)


class TestXor(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(ciphers.xor_single(ciphers.xor_single("secret", 42), 42), "secret")

    def test_key_out_of_range(self):
        with self.assertRaises(ValueError):
            ciphers.xor_single("abc", 256)

    def test_bruteforce_finds_key(self):
        plain = "the quick brown fox jumps over the lazy dog"
        cipher = ciphers.xor_single(plain, 0x5A)
        key, best, _ = ciphers.xor_bruteforce(cipher)[0]
        self.assertEqual(key, 0x5A)
        self.assertEqual(best, plain)


class TestEnglishScore(unittest.TestCase):
    def test_english_beats_random(self):
        self.assertGreater(ciphers.english_score("the quick brown fox"), ciphers.english_score("qzxv jkwbp"))

    def test_empty(self):
        self.assertEqual(ciphers.english_score(""), float("-inf"))

    def test_flag_bonus_detects_prefix(self):
        self.assertGreater(ciphers.flag_bonus("flag{abc}"), 0)
        self.assertGreater(ciphers.flag_bonus("HTB{abc}"), 0)
        self.assertEqual(ciphers.flag_bonus("just text"), 0.0)

    def test_flag_ranks_above_english_lookalike(self):
        # A real flag scores worse on pure English than a shifted lookalike;
        # the flag prefix bonus must put the real one first.
        cipher = ciphers.caesar("flag{ch41n_w0rks}", 7)
        shift, best, _ = ciphers.caesar_bruteforce(cipher)[0]
        self.assertEqual(best, "flag{ch41n_w0rks}")


class TestFlagInBruteforce(unittest.TestCase):
    def test_xor_bruteforce_finds_flag(self):
        cipher = ciphers.xor_single("flag{x0r_brut3}", 0x33)
        key, best, _ = ciphers.xor_bruteforce(cipher)[0]
        self.assertEqual(best, "flag{x0r_brut3}")


if __name__ == "__main__":
    unittest.main()
