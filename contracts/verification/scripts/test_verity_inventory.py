#!/usr/bin/env python3
"""Executable negative controls against the actual pinned Lean compiler."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_verity_inventory as gate


class CensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = gate.source_snapshot(gate.VERITY)
        cls.good = gate.fresh_inventory(cls.source)

    def compile_change(self, text, *, name="Top", prepend=False):
        source = dict(self.source)
        path = f"PQSigner/Verifier/{name}.lean"
        source[path] = ((text.encode() + source[path]) if prepend else (source[path] + text.encode()))
        # Compilation must succeed; an elaboration error is not rejection evidence.
        return source, gate.fresh_inventory(source)

    def test_baseline_and_cache_independence(self):
        self.assertEqual(gate.validate(self.source, self.good)["admitted_declarations"], 1)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, data in self.source.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            cached = root / ".lake/build/lib/lean/PQSigner/Verifier/Top.olean"
            cached.parent.mkdir(parents=True)
            cached.write_bytes(b"deliberately stale invalid compiled artifact")
            with patch.dict("os.environ", {"LEAN_PATH": str(cached.parent), "ELAN_TOOLCHAIN": "invalid", "LEAN_SYSROOT": "/nonexistent"}):
                self.assertEqual(gate.census(root)["compiled_modules"], 8)

    def test_closed_proof_is_allowed(self):
        source, inventory = self.compile_change("\ntheorem census_positive : 2 + 2 = 4 := by decide\n")
        gate.validate(source, inventory)

    def test_macro_named_private_and_suppressed_holes(self):
        for declaration in ("theorem census_new", "private theorem census_private",
                            "set_option warn.sorry false in\ntheorem census_suppressed"):
            with self.subTest(declaration=declaration):
                source, inventory = self.compile_change(f"\n{declaration} : False := by stop trivial\n")
                with self.assertRaisesRegex(ValueError, "unapproved or changed admitted"):
                    gate.validate(source, inventory)

    def test_transitive_hole_dependency(self):
        source, inventory = self.compile_change("\n def census_alias := @PQSigner.Verifier.Merkle.yul_swap_selector_in_known_set\n")
        with self.assertRaisesRegex(ValueError, "unapproved or changed admitted"):
            gate.validate(source, inventory)

    def test_axiom_identity_and_type(self):
        source, inventory = self.compile_change("\naxiom census_new_axiom : True\n")
        with self.assertRaisesRegex(ValueError, "axiom identity/type"):
            gate.validate(source, inventory)
        source = dict(self.source)
        p = "PQSigner/Verifier/Hash.lean"
        self.assertIn(b"axiom sha256_deterministic", source[p])
        # Add an optional argument: callers still elaborate, but the axiom type changes.
        source[p] = source[p].replace(b"axiom sha256_deterministic (a b : ByteVec) (h : a = b)",
            b"axiom sha256_deterministic (a b : ByteVec) (h : a = b) (extra : True := True.intro)")
        with self.assertRaisesRegex(ValueError, "axiom identity/type"):
            gate.validate(source, gate.fresh_inventory(source))

    def test_generated_hole(self):
        # This elaborator emits a declaration without any source proof-hole keyword.
        code = '''import Lean
open Lean Elab Command in
elab "census_emit" : command => do
  liftCoreM <| addAndCompile <| Declaration.thmDecl {
    name := `census_generated, levelParams := [], type := mkConst ``False,
    value := mkApp2 (mkConst (Name.mkSimple ("sor" ++ "ryAx")) [Level.zero])
      (mkConst ``False) (mkConst ``Bool.true) }
census_emit
'''
        source = dict(self.source)
        path = "PQSigner/Verifier/Top.lean"
        source[path] = b"import Lean\n" + source[path] + code.removeprefix("import Lean\n").encode()
        inventory = gate.fresh_inventory(source)
        generated = next(d for d in inventory["declarations"] if d["name"] == "census_generated")
        self.assertIn("sorryAx", generated["axioms"])
        with self.assertRaisesRegex(ValueError, "axiom identity/type|unapproved or changed admitted"):
            gate.validate(source, inventory)

    def test_sibling_axiom_cannot_be_subsumed(self):
        source = dict(self.source)
        source["PQSigner/Verifier/Wots.lean"] += b"""
namespace PQSigner.Verifier.Merkle
axiom auth_path_depth_eq_SUBTREE_H : PQSigner.Verifier.Params.SUBTREE_H = 9
end PQSigner.Verifier.Merkle
"""
        # Both module compilations accept this. The combined import chooses
        # Merkle's theorem over Wots' axiom, so inspect the original module data.
        with self.assertRaisesRegex(ValueError, "Duplicate project declaration"):
            gate.fresh_inventory(source)

    def test_unchecked_declaration_is_rejected_by_kernel(self):
        source = dict(self.source)
        p = "PQSigner/Verifier/Top.lean"
        code = """
open Lean Elab Command in
elab "census_unchecked" : command => do
  liftCoreM <| withOptions (fun opts => debug.skipKernelTC.set opts true) <| addDecl <|
    Declaration.thmDecl {
      name := `census_unchecked_false, levelParams := [],
      type := mkConst ``False, value := mkConst ``True.intro }
census_unchecked
theorem census_derived_false : False := census_unchecked_false
"""
        source[p] = b"import Lean\n" + source[p] + code.encode()
        # All eight compilations accept this source. The separate census process
        # must reject the exported invalid proof specifically at kernel replay.
        with self.assertRaisesRegex(ValueError, r"kernel.*type mismatch"):
            gate.fresh_inventory(source)

    def test_changed_or_removed_admitted_obligation(self):
        p = "PQSigner/Verifier/Merkle.lean"
        for mutation in ("statement", "body", "delete"):
            with self.subTest(mutation=mutation):
                source = dict(self.source)
                if mutation == "statement":
                    source[p] = source[p].replace(
                        b"(idx &&& 1) <<< 5 = 0 \xe2\x88\xa8 (idx &&& 1) <<< 5 = 0x20 := by",
                        b"False := by")
                elif mutation == "body":
                    source[p] = source[p].replace(b"  sorry\n", b"  have injected : False := by stop trivial\n  exact injected.elim\n")
                else:
                    start = source[p].index(b"theorem yul_swap_selector_in_known_set")
                    start = source[p].rfind(b"/--", 0, start)
                    end = source[p].index(b"/-! ### Determinism", start)
                    source[p] = source[p][:start] + source[p][end:]
                self.assertNotEqual(source[p], self.source[p])
                with self.assertRaisesRegex(ValueError, "admitted"):
                    gate.validate(source, gate.fresh_inventory(source))

    def test_part_a_quarantine_and_duplicate_manifest(self):
        for name in gate.QUARANTINE:
            source = dict(self.source)
            source[name] += b"\n-- changed source-only obligation\n"
            with self.assertRaisesRegex(ValueError, "quarantine"):
                gate.validate(source, self.good)
        source = dict(self.source)
        source["assurance_inventory.json"] = b'{"schema_version":1,"schema_version":1}'
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            gate.validate(source, self.good)

    def test_source_coverage_links_and_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, data in self.source.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            extra = root / "Orphan.lean"
            extra.write_text("axiom hidden : False\n")
            with self.assertRaisesRegex(ValueError, "coverage mismatch"):
                gate.source_snapshot(root)
            extra.unlink()
            extra.symlink_to(root / gate.MODULES[0])
            with self.assertRaisesRegex(ValueError, "symlink"):
                gate.source_snapshot(root)
            extra.unlink()
            def mutate(snapshot):
                (root / gate.MODULES[0]).write_bytes(snapshot[gate.MODULES[0]] + b"\n")
                return self.good
            with patch.object(gate, "fresh_inventory", side_effect=mutate):
                with self.assertRaisesRegex(ValueError, "changed during execution"):
                    gate.census(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
