#!/usr/bin/env python3
"""Negative controls for source, signature and axiom enrollment."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import verify


class GateControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ["StreamingHistory.lean", "profile.json"]:
            shutil.copyfile(verify.HERE / name, self.root / name)
        shutil.copytree(verify.HERE / "source", self.root / "source")

    def config(self, change):
        path = self.root / "profile.json"
        data = json.loads(path.read_text())
        change(data)
        path.write_text(json.dumps(data))

    def test_baseline(self):
        self.assertEqual(len(verify.check_sources(self.root)[0]["axioms"]), 38)

    def test_changed_source(self):
        path = self.root / "StreamingHistory.lean"
        path.write_text(path.read_text().replace("checkedMul 8 total", "checkedMul 7 total"))
        with self.assertRaisesRegex(ValueError, "source identity"):
            verify.check_sources(self.root)

    def test_missing_proof_pin(self):
        self.config(lambda c: c["source_sha256"].pop("StreamingHistory.lean"))
        with self.assertRaisesRegex(ValueError, "missing proof source"):
            verify.check_sources(self.root)

    def test_missing_mapping_pin(self):
        self.config(lambda c: c["source_sha256"].pop("source/sha2-0.10.9/src/core_api.rs"))
        with self.assertRaisesRegex(ValueError, "source map pin"):
            verify.check_sources(self.root)

    def test_missing_headline(self):
        self.config(lambda c: c["axioms"].pop("history_bitLength"))
        with self.assertRaisesRegex(ValueError, "theorem enrollment"):
            verify.check_sources(self.root)

    def test_changed_signature(self):
        self.config(lambda c: c["signature_sha256"].update(history_bitLength="0" * 64))
        with self.assertRaisesRegex(ValueError, "theorem signatures"):
            verify.check_sources(self.root)

    def test_banned_shortcut_even_with_rebound_source(self):
        path = self.root / "StreamingHistory.lean"
        path.write_text(path.read_text().replace("  decide", "  native_decide"))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.config(lambda c: c["source_sha256"].update({"StreamingHistory.lean": digest}))
        with self.assertRaisesRegex(ValueError, "proof shortcut"):
            verify.check_sources(self.root)

    def test_foreign_axiom(self):
        with self.assertRaisesRegex(ValueError, "unapproved axiom"):
            verify.census("'StreamingHistory.history_bitLength' depends on axioms: [sorryAx]\n")

    def test_duplicate_census(self):
        line = "'StreamingHistory.history_bitLength' depends on axioms: [propext]\n"
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify.census(line + line)

    def test_diagnostic_is_not_census(self):
        with self.assertRaisesRegex(ValueError, "unexpected"):
            verify.census("warning: declaration uses sorry\n")


if __name__ == "__main__":
    unittest.main()
