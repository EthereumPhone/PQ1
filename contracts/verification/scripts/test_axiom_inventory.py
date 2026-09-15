#!/usr/bin/env python3
"""Regression probes for hidden declarations and proof-hole aliases."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import check_axiom_inventory as census
from check_verity_holes import check as check_holes
from lean_source import keyword_count


# These are complete, buildable Lean commands, including custom syntax probes.
COMMENT_AXIOMS = [
    "/-/- -/ axiom X : False -- -/\n",
    "/--/ -- -/ axiom X : False\n",
    "def n : Nat := 0axiom X : False\n",
    "def c : Char := 'a'axiom X : False\n",
    'macro "中" : command => `(#check True)\n中axiom X : False\n',
]
COMMENT_HOLES = [
    "/-/- -/ theorem X : False := by sorry -- -/\n",
    "/--/ -- -/ theorem X : False := by sorry\n",
    'postfix:max "中" => id\ntheorem X : False := sorry中\n',
    'syntax:1024 num term:1024 : term\n'
    'macro_rules | `($n:num $t:term) => `($t)\n'
    'theorem X : False := 0sorry\n',
]


CUSTOM_AXIOMS = [
    'macro ":/-" : command => `(#check True)\n:/- axiom X : False -- -/\n',
    'macro "/--x" : command => `(#check True)\n/--x axiom X : False -- -/\n',
    'macro ":--" : command => `(#check True)\n:-- axiom X : False\n',
    'macro ":«" s:str : command => `(#check $s)\n:« "»--" axiom X : False\n',
    r'macro "x\u002f\u002d" : command => `(#check True)' + "\n" +
    r'macro "\u002d\u002f" : command => `(#check True)' + "\nx/-axiom X : False -/\n",
    r'macro "x\u002d\u002d" : command => `(#check True)' + "\nx--axiom X : False\n",
]
CUSTOM_HOLES = [
    'macro ":/-" : command => `(#check True)\n:/- theorem X : False := by sorry -- -/\n',
    'macro "/--x" : command => `(#check True)\n/--x theorem X : False := by sorry -- -/\n',
    'macro ":«" s:str : command => `(#check $s)\n:« "»--" theorem X : False := by sorry\n',
    r'macro "x\u002d\u002d" : command => `(#check True)' + "\nx--theorem X : False := by sorry\n",
]

class SourceTests(unittest.TestCase):
    def test_comments_and_strings(self):
        for prefix in [
            'import Lean\nopen Lean Parser\ndef p : Parser := leading_parser"\\" -- " ',
            'example : String := by refine\'"\' -- " ',
            'def a := s! "{ "--" }" ',
            'def a := s! /- gap -/ "{ "--" }" ',
            'def a := s!\n"{ "--" }" ',
            'def a : String := dbg_trace "{ "--" }"; "" ',
            'def a := r"\\" def b := "--" ',
            'def s := "-- /-"\n',
            'def s := r##"-- /- " quoted"##\n',
            'def s := s!"{ "-- /-" }"\n',
            'def «/-» := 1\n',
            "def c := '\"'\n",
        ]:
            self.assertEqual(keyword_count(prefix + "private axiom X : False", "axiom"), 1)
        # Comments, quoted text and even incomplete syntax are never erased.
        self.assertEqual(keyword_count("-- admit\n/- sorry /- admit -/ sorry -/", "(?:sorry|admit)"), 4)
        self.assertEqual(keyword_count('/- axiom /- axiom -/ axiom -/ axiom X : False', "axiom"), 4)
        self.assertEqual(keyword_count('/- unclosed axiom', "axiom"), 1)

    def test_comment_and_token_boundaries(self):
        for source in COMMENT_AXIOMS + CUSTOM_AXIOMS:
            self.assertEqual(keyword_count(source, "axiom"), 1)
        for source in COMMENT_HOLES + CUSTOM_HOLES:
            self.assertEqual(keyword_count(source, "(?:sorry|admit|sorryAx|proof_wanted)"), 1)
        # Deliberate over-counting binds dump modules and cannot hide a keyword.
        self.assertEqual(keyword_count("#print axioms t", "axiom"), 1)

    def test_source_mutations(self):
        for project, root in census.PROJECTS.items():
            original = census.SCRIPTS.parent / project
            expected = json.loads((census.SCRIPTS / f"axiom_inventory_{project}.json").read_text())["source"]
            with tempfile.TemporaryDirectory() as temp:
                target = Path(temp)
                shutil.copytree(original / root, target / root)
                shutil.copy2(original / f"{root}.lean", target / f"{root}.lean")
                self.assertEqual(census.source_inventory(target, root), expected)
                # New, deliberately unimported modules must also be counted.
                probe = target / root / "CensusProbe.lean"
                for extra in COMMENT_AXIOMS + CUSTOM_AXIOMS + [
                    'import Lean\nopen Lean Parser\ndef p : Parser := leading_parser"\\" -- " axiom X : False\n',
                    'example : String := by refine\'"\' -- " axiom X : False\n',
                    'def a := s! "{ "--" }" axiom X : False\n',
                    'def a := s! /- gap -/ "{ "--" }" axiom X : False\n',
                    'def a := s!\n"{ "--" }" axiom X : False\n',
                    'def a : String := dbg_trace "{ "--" }"; "" axiom X : False\n',
                    'def a := r"\\" def b := "--" private axiom X : False\n',
                    "private axiom X : False\n",
                    "namespace Other\naxiom keccak256_pure : False\nend Other\n",
                    'def s := s!"{ "--" }"\nprivate axiom X : False\n',
                    "axiom X : True axiom Y : False\n",
                ]:
                    probe.write_text(extra)
                    with self.assertRaises(ValueError):
                        census.compare(expected, census.source_inventory(target, root), "source")
                probe.unlink()
                pinned = target / ("SphincsCVerify/Bridge/Refinement.lean" if project == "lean"
                                   else "Extracted/SlotKdf/FunsExternal.lean")
                data = pinned.read_bytes()
                for changed in [data + b"\nprivate axiom X : False\n", data.replace(b"axiom ", b"private axiom ", 1),
                                b"namespace Changed\n" + data + b"\nend Changed\n"]:
                    pinned.write_bytes(changed)
                    with self.assertRaises(ValueError):
                        census.compare(expected, census.source_inventory(target, root), "source")
                pinned.write_bytes(data)
                # Quarantine imports in the root, including second-on-line imports.
                rootfile = target / f"{root}.lean"
                for extra in ["import Extracted.AxiomCheckNegativeControl\n",
                              "import Lean Extracted.AxiomCheckNegativeControl\n",
                              "import Extracted.«AxiomCheckNegativeControl»\n",
                              "/-/- -/ import Extracted.AxiomCheckNegativeControl -- -/\n"]:
                    rootfile.write_text(extra)
                    with self.assertRaises(ValueError):
                        census.source_inventory(target, root)

    def test_elaborated_inventory(self):
        row = {"name": "Private.X", "module": "Module", "type": "False", "levels": [], "unsafe": False}
        expected = census.elaborated_inventory([row])
        for key, value in [("name", "Other.X"), ("module", "OtherModule"), ("type", "True")]:
            mutant = copy.deepcopy(row)
            mutant[key] = value
            with self.assertRaises(ValueError):
                census.compare(expected, census.elaborated_inventory([mutant]), "elaborated")
        for rows in [[], [row, row]]:
            with self.assertRaises(ValueError):
                census.elaborated_inventory(rows)

    def test_verity_prose_is_not_an_allowance(self):
        original = census.SCRIPTS.parents[1] / "verity"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copytree(original / "PQSigner", root / "PQSigner")
            self.assertEqual(check_holes(root), 12)
            path = root / "PQSigner/Theorems.lean"
            data = path.read_bytes()
            path.write_bytes(data + b"\ntheorem Extra : False := by sorry\n")
            with self.assertRaises(ValueError):
                check_holes(root)
            path.write_bytes(data)
            # There is no exemption that could turn comments into extra holes.
            probe = root / "PQSigner/ProseProbe.lean"
            probe.write_text("-- sorry in prose\n")
            with self.assertRaises(ValueError):
                check_holes(root)
            probe.write_text('def text := "admit"\n')
            with self.assertRaises(ValueError):
                check_holes(root)

    def test_verity_aliases(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "PQSigner").mkdir()
            path = root / "PQSigner/Probe.lean"
            path.write_text("-- ordinary prose\nexample : True := by trivial\n")
            self.assertEqual(check_holes(root), 0)
            for code in COMMENT_HOLES + CUSTOM_HOLES + [
                         'import Lean\nopen Lean Parser\ndef p : Parser := leading_parser"\\" -- " theorem X : False := by admit',
                         'import Lean\nopen Lean Parser\ndef p : Parser := leading_parser"\\" -- " theorem X : False := by sorry',
                         'example : String := by refine\'"\' -- " theorem X : False := by admit',
                         'example : String := by refine\'"\' -- " theorem X : False := by sorry',
                         'def a := s! "{ "--" }" theorem X : False := by admit',
                         'def a := s! "{ "--" }" theorem X : False := by sorry',
                         'def a := s! /- gap -/ "{ "--" }" theorem X : False := by admit',
                         'def a := s! /- gap -/ "{ "--" }" theorem X : False := by sorry',
                         'def a := s!\n"{ "--" }" theorem X : False := by admit',
                         'def a := s!\n"{ "--" }" theorem X : False := by sorry',
                         'def a : String := dbg_trace "{ "--" }"; "" theorem X : False := by admit',
                         'def a : String := dbg_trace "{ "--" }"; "" theorem X : False := by sorry',
                         'def a := r"\\" def b := "--" theorem X : False := by admit',
                         'def a := r"\\" def b := "--" theorem X : False := by sorry',
                         "example : False := by admit", "example : False := by sorry",
                         'example : False := by\n  let s := "--"; admit',
                         'example : False := by\n  let s := s!"{ "--" }"; admit']:
                path.write_text(code)
                with self.assertRaises(ValueError):
                    check_holes(root)


if __name__ == "__main__":
    unittest.main()
