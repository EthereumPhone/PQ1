#!/usr/bin/env python3
"""Offline unit tests for the fast Kani census manifest checks."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kani_census


class ManifestRotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "crate/src/lib.rs"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(
            "#[kani::proof]\nfn binds_value() {\n    let guarded = true;\n}\n",
            encoding="utf-8",
        )
        self.census = {
            "_file_harnesses": {"crate/src/lib.rs": ["binds_value"]},
        }
        self.entry = {
            "id": "guard",
            "file": "crate/src/lib.rs",
            "harness": "binds_value",
            "find": "let guarded = true;",
            "replace": "let guarded = false;",
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def failures(self, entry: dict) -> list[str]:
        return kani_census.manifest_rot(
            self.census,
            manifest={"mutations": [entry]},
            repo_root=self.root,
        )

    def test_accepts_one_material_mutation_bound_to_existing_harness(self) -> None:
        self.assertEqual(self.failures(self.entry), [])

    def test_rejects_missing_file_or_harness(self) -> None:
        missing_file = dict(self.entry, file="crate/src/missing.rs")
        missing_harness = dict(self.entry, harness="renamed")
        self.assertIn("does not exist", self.failures(missing_file)[0])
        self.assertIn("no `#[kani::proof] fn renamed`", self.failures(missing_harness)[0])

    def test_rejects_empty_absent_or_ambiguous_find_string(self) -> None:
        self.assertIn("missing or empty", self.failures(dict(self.entry, find=""))[0])
        self.assertIn("occurs 0x", self.failures(dict(self.entry, find="not present"))[0])

        self.source.write_text(
            "#[kani::proof]\nfn binds_value() {\n"
            "    let guarded = true;\n    let guarded = true;\n}\n",
            encoding="utf-8",
        )
        self.assertIn("occurs 2x", self.failures(self.entry)[0])

    def test_rejects_noop_or_non_string_replacement(self) -> None:
        noop = dict(self.entry, replace=self.entry["find"])
        non_string = dict(self.entry, replace=None)
        self.assertIn("replace == find", self.failures(noop)[0])
        self.assertIn("replacement must be a string", self.failures(non_string)[0])

    def test_harness_census_ignores_commented_proof_attribute(self) -> None:
        text = """\
// Kani `#[kani::proof]` harnesses do not execute under cargo test.
fn ordinary_test() {}
"""
        self.assertEqual(kani_census.harnesses_in(text), [])

    def test_harness_census_binds_normal_standalone_attribute(self) -> None:
        text = """\
    #[kani::proof]
    #[kani::unwind(8)]
    // The function may be separated from the proof attribute.

    fn panic_free() {}
"""
        self.assertEqual(kani_census.harnesses_in(text), ["panic_free"])


class CrossFileAndCfgGateTests(unittest.TestCase):
    """Issue #659 (cross-file mutation/harness pairs) and #662 (cfg-gated
    harnesses must carry matching z_flags)."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        helper = self.root / "crate/src/helper.rs"
        helper.parent.mkdir(parents=True)
        helper.write_text(
            "pub fn decide(x: u32) -> bool {\n    x == 0 || x > 7\n}\n",
            encoding="utf-8",
        )
        caller = self.root / "crate/src/caller.rs"
        caller.write_text(
            "#[kani::proof]\nfn decision_binds() {\n    assert!(true);\n}\n",
            encoding="utf-8",
        )
        gated = self.root / "crate/src/gated.rs"
        gated.write_text(
            "/// doc comment between the gate and the proof attr\n"
            "#[cfg(feature = \"kani-heavy\")]\n"
            "#[kani::proof]\n"
            "#[kani::unwind(101)]\n"
            "fn heavy_harness() {\n    let guarded = true;\n}\n",
            encoding="utf-8",
        )
        self.census = {
            "_file_harnesses": {
                "crate/src/caller.rs": ["decision_binds"],
                "crate/src/gated.rs": ["heavy_harness"],
            },
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def failures(self, entry: dict) -> list[str]:
        return kani_census.manifest_rot(
            self.census,
            manifest={"mutations": [entry]},
            repo_root=self.root,
        )

    def test_cross_file_harness_pair_is_accepted(self) -> None:
        # #659: the mutation anchors a shared helper in helper.rs while the
        # covering harness lives in caller.rs.
        entry = {
            "id": "x",
            "file": "crate/src/helper.rs",
            "harness": "decision_binds",
            "find": "    x == 0 || x > 7",
            "replace": "    x <= 0 || x > 7",
        }
        self.assertEqual(self.failures(entry), [])

    def test_cfg_gated_harness_without_z_flags_fails_statically(self) -> None:
        # #662: a cfg(kani-heavy)-gated harness with no --features flag would
        # compile OUT in the slow lane (no verdict, HarnessError). Dies here.
        entry = {
            "id": "g",
            "file": "crate/src/gated.rs",
            "harness": "heavy_harness",
            "find": "let guarded = true;",
            "replace": "let guarded = false;",
        }
        fails = self.failures(entry)
        self.assertEqual(len(fails), 1)
        self.assertIn("cfg-gated", fails[0])
        self.assertIn("kani-heavy", fails[0])

    def test_cfg_gated_harness_with_matching_z_flags_passes(self) -> None:
        entry = {
            "id": "g",
            "file": "crate/src/gated.rs",
            "harness": "heavy_harness",
            "find": "let guarded = true;",
            "replace": "let guarded = false;",
            "z_flags": ["--features", "kani-heavy"],
        }
        self.assertEqual(self.failures(entry), [])
        entry_eq = dict(entry, z_flags=["--features=kani-heavy"])
        self.assertEqual(self.failures(entry_eq), [])

    def test_multiline_cfg_cannot_hide_required_feature(self) -> None:
        p = self.root / 'crate/src/gated.rs'
        p.write_text(p.read_text().replace('#[cfg(feature = "kani-heavy")]',
                                          '#[cfg(\n    feature = "kani-heavy"\n)]'))
        entry = dict(id='g', file='crate/src/gated.rs', harness='heavy_harness',
                     find='let guarded = true;', replace='let guarded = false;')
        self.assertIn('cfg-gated', self.failures(entry)[0])
        self.assertEqual(self.failures(dict(entry, z_flags=['--features', 'kani-heavy'])), [])

    def test_unsupported_feature_expression_fails_explicitly(self) -> None:
        p = self.root / 'crate/src/gated.rs'
        p.write_text(p.read_text().replace('cfg(feature = "kani-heavy")',
                                          'cfg(not(feature = "kani-heavy"))'))
        entry = dict(id='g', file='crate/src/gated.rs', harness='heavy_harness',
                     find='let guarded = true;', replace='let guarded = false;',
                     z_flags=['--features', 'kani-heavy'])
        self.assertIn('unsupported feature cfg', self.failures(entry)[0])


if __name__ == "__main__":
    unittest.main()
