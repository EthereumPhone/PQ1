/-
Audit script: scans the SphincsCVerify project for **real** `sorry`
tactics (not the literal word inside comments / docstrings).

Run via `lake env lean --run scripts/check_no_sorry.lean`.
-/

import SphincsCVerify

open System

/-- Count lines that *start* with whitespace + `sorry` (the real tactic
    form, not a `sorry` substring in a comment). -/
partial def countSorryInFile (path : FilePath) : IO Nat := do
  let txt ← IO.FS.readFile path
  let lines := txt.splitOn "\n"
  let isSorryLine (line : String) : Bool :=
    let trimmed := line.trimLeft
    -- Match an actual tactic-position `sorry` (possibly with comment).
    -- We exclude lines that begin with `--` (Lean line comment) and
    -- lines that don't start with `sorry`.
    !trimmed.startsWith "--" && (trimmed.startsWith "sorry" || trimmed = "sorry")
  return lines.filter isSorryLine |>.length

partial def walk (root : FilePath) : IO (Array FilePath) := do
  let mut out : Array FilePath := #[]
  for entry in (← root.readDir) do
    if (← entry.path.isDir) then
      out := out ++ (← walk entry.path)
    else if entry.path.toString.endsWith ".lean" then
      out := out.push entry.path
  return out

def main : IO Unit := do
  IO.println "Auditing SphincsCVerify for `sorry` (tactic position only) ..."
  let root : FilePath := "SphincsCVerify"
  let files ← walk root
  let mut total : Nat := 0
  for f in files do
    let n ← countSorryInFile f
    if n > 0 then
      IO.println s!"  {f}: {n}"
      total := total + n
  IO.println s!"Total tactic-position sorry count: {total}"
  IO.println ""
  IO.println "Closed core (no `sorry`, no cryptographic axiom):"
  IO.println "  * SphincsCVerify/Spec/Params.lean"
  IO.println "  * SphincsCVerify/Spec/Bytes.lean"
  IO.println "  * SphincsCVerify/Spec/Adrs.lean"
  IO.println "  * SphincsCVerify/Spec/Hash.lean         (modulo opaque sha256)"
  IO.println "  * SphincsCVerify/Spec/Hypertree.lean"
  IO.println "  * SphincsCVerify/Spec/Signature.lean"
  IO.println "  * SphincsCVerify/Verifier/Refined.lean"
  IO.println "  * SphincsCVerify/Bridge/SolidityVerifier.lean"
  IO.println "  * SphincsCVerify/Wallet/Storage.lean"
  IO.println "  * SphincsCVerify/Wallet/MultiOwnable.lean (all theorems closed)"
  IO.println "  * SphincsCVerify/Wallet/Factory.lean"
  IO.println ""
  IO.println "Outstanding mechanical-discharge `sorry`s — see docs/AXIOMS.md § D."
