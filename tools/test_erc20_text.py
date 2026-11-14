#!/usr/bin/env python3
"""Unit tests for tools/erc20_text.py (the shared ERC-20 name/symbol sanitizer).

Run: python3 -m unittest tools/test_erc20_text.py
"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import erc20_text as t  # noqa: E402


class SafeFolds(unittest.TestCase):
    def test_tether_tugrik(self):
        self.assertEqual(t.clean_symbol("USD₮0"), "USDT0")
        self.assertEqual(t.clean_symbol("aUSD₮"), "aUSDT")
        self.assertEqual(t.clean_name("Stargate USD₮0 (Bridged)"), "Stargate USDT0 (Bridged)")

    def test_currency_signs(self):
        self.assertEqual(t.clean_name("Backed HIGH € High Yield Corp Bond"),
                         "Backed HIGH EUR High Yield Corp Bond")
        self.assertEqual(t.clean_name("£ Coin"), "GBP Coin")

    def test_quotes_and_dashes(self):
        self.assertEqual(t.clean_name("JPEG’d Governance Token"), "JPEG'd Governance Token")
        self.assertEqual(t.clean_name("‘a’ “b”"), "'a' \"b\"")
        self.assertEqual(t.clean_name("PathOS – your sentient AI guide."),
                         "PathOS - your sentient AI guide.")

    def test_latin_letters(self):
        self.assertEqual(t.clean_name("EURØP"), "EUROP")
        self.assertEqual(t.clean_name("søster"), "soster")
        self.assertEqual(t.clean_name("Straße"), "Strasse")

    def test_marks(self):
        self.assertEqual(t.clean_name("Starly the $STAR™ Guide"), "Starly the $STAR(TM) Guide")
        self.assertEqual(t.clean_name("S&P500® Fund"), "S&P500(R) Fund")


class CombiningMarks(unittest.TestCase):
    def test_diacritics_removed(self):
        self.assertEqual(t.clean_name("Real Brasileño"), "Real Brasileno")
        self.assertEqual(t.clean_name("Göztepe S.K."), "Goztepe S.K.")
        self.assertEqual(t.clean_name("İstanbul Başakşehir FK"), "Istanbul Basaksehir FK")
        self.assertEqual(t.clean_name("Club Atlético Independiente"),
                         "Club Atletico Independiente")
        self.assertEqual(t.clean_symbol("LAÏKA"), "LAIKA")

    def test_decomposed_input(self):
        # "e" + COMBINING ACUTE ACCENT
        self.assertEqual(t.clean_name("Café"), "Cafe")


class NoLookalikeFolding(unittest.TestCase):
    def test_cyrillic_dropped(self):
        self.assertIsNone(t.clean_symbol("шайлушай"))
        # Cyrillic capital ES looks like Latin C
        self.assertIsNone(t.clean_symbol("USDС"))
        self.assertIsNone(t.clean_name("Ж"))

    def test_greek_dropped(self):
        self.assertIsNone(t.clean_symbol("τBTC"))
        self.assertIsNone(t.clean_name("Taτsu"))
        self.assertIsNone(t.clean_symbol("SΞR"))
        self.assertIsNone(t.clean_symbol("αHYPE"))

    def test_armenian_dropped(self):
        # Armenian capital SEH looks like Latin U
        self.assertIsNone(t.clean_symbol("ՍSDT"))

    def test_other_scripts_and_symbols_dropped(self):
        for s in ("喵喵喵喵喵", "ハチ公", "마라도", "٨", "⚗️", "REDFEG 🦍",
                  "BTC.ℏ[eth]", "₸USD", "100¥", "Raid Guild Token ⚔️"):
            with self.subTest(s=s):
                self.assertIsNone(t.clean_symbol(s))
                self.assertIsNone(t.clean_name(s))

    def test_yen_not_guessed(self):
        self.assertIsNone(t.clean_symbol("¥"))

    def test_zero_width_not_silently_removed(self):
        # A zero-width space inside a ticker is an impersonation trick; it is
        # not a control character, so the row is dropped rather than folded.
        self.assertIsNone(t.clean_symbol("US​DT"))


class Whitespace(unittest.TestCase):
    def test_controls_and_collapse(self):
        self.assertEqual(t.clean_name("  A\t\nB  \x00C "), "A B C")
        self.assertEqual(t.clean_name("A B"), "A B")

    def test_empty(self):
        for s in ("", "   ", "\x00\x01", None, 5):
            with self.subTest(s=s):
                self.assertIsNone(t.clean_name(s))
                self.assertIsNone(t.clean_symbol(s))


class Length(unittest.TestCase):
    def test_ondo_suffix(self):
        n = "iShares Euro High Yield Corporate Bond USD Hedged ETF (Ondo Tokenized)"
        self.assertEqual(t.clean_name(n),
                         "iShares Euro High Yield Corporate Bond USD Hedged ETF (Ondo)")

    def test_ondo_suffix_still_too_long_is_cut(self):
        n = "A" * 10 + " " + "B" * 60 + " (Ondo Tokenized)"
        out = t.clean_name(n)
        self.assertLessEqual(len(out), 64)
        self.assertTrue(out.endswith("..."))

    def test_word_boundary_cut(self):
        n = ("Sony Group Corporation American Depositary Shares (Each "
             "Representing One Share of Dollar Validated Common Stock) - Dinari")
        out = t.clean_name(n)
        self.assertEqual(out, "Sony Group Corporation American Depositary Shares (Each...")
        self.assertLessEqual(len(out), 64)

    def test_hard_cut_without_boundary(self):
        n = "IP Tokens of IPNFT #" + "1" * 80
        out = t.clean_name(n)
        self.assertEqual(out, "IP Tokens of IPNFT...")
        self.assertEqual(t.clean_name("X" * 100), "X" * 61 + "...")

    def test_exact_limits(self):
        self.assertEqual(t.clean_name("N" * 64), "N" * 64)
        self.assertEqual(t.clean_symbol("S" * 64), "S" * 64)

    def test_long_symbol_dropped(self):
        self.assertIsNone(t.clean_symbol("S" * 65))


class Invariants(unittest.TestCase):
    SAMPLES = [
        "USD₮0", "Real Brasileño", "Backed ERNX € Ultrashort Bond",
        "iShares Global Government Bond USD Hedged Active ETF (Ondo Tokenized)",
        "IP Tokens of IPNFT #108246717199802830449916199897226478163176946134490555322418727943986180682745",
        "  plain  ", "X" * 200, "a ’ b",
    ]

    def test_idempotent_and_device_verifiable(self):
        for s in self.SAMPLES:
            for f in (t.clean_name, t.clean_symbol):
                with self.subTest(s=s, f=f.__name__):
                    out = f(s)
                    if out is None:
                        continue
                    self.assertTrue(t.is_device_text(out))
                    self.assertEqual(f(out), out)

    def test_ascii_passthrough(self):
        for s in ("USDC", "Wrapped Ether", "~ !$%&()*+,-./:;<=>?@[]^_`{|}~"):
            self.assertEqual(t.clean_name(s), s)
            self.assertEqual(t.clean_symbol(s), s)

    def test_basic_clean_keeps_unicode(self):
        self.assertEqual(t.basic_clean(" USD₮0\n"), "USD₮0")


if __name__ == "__main__":
    unittest.main()
