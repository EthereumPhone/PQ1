/- Executed checks supplement the universal WOTS component bridges. -/
import Extracted.WotsSpecBridge
import Extracted.WotsBridgeDiffVectors

namespace WotsBridgeDiff
open Aeneas Aeneas.Std Extracted.Equiv

def word (bs : Array UInt8) : Option (Std.Array Std.U8 32#usize) :=
  let l := bs.toList.map Sha256Pure.ofUInt8
  if h : l.length = 32 then some ⟨l, by simpa using h⟩ else none

def hashRun (words : Array (Array UInt8)) (count : Nat) :
    Option (Array UInt8 × Array UInt8) := do
  if words.size != 3 || count ≥ 2^32 then none else do
    let seed ← word words[0]!
    let adrs ← word words[1]!
    let message ← word words[2]!
    match sphincs_c10.hash.wots_digest seed adrs message ⟨BitVec.ofNat 32 count⟩ with
    | .ok d => some ((toSpecDigest d).data,
        (SphincsCVerify.Spec.wotsDigest (toSpecDigest seed) (toSpecDigest adrs)
          (toSpecDigest message) (UInt32.ofNat count)).data)
    | _ => none

def hashAgrees (words : Array (Array UInt8)) (count : Nat) (expected : Array UInt8) : Bool :=
  match hashRun words count with
  | some (a,b) => a == expected && b == expected
  | none => false

def digitRun (bytes : Array UInt8) : Option (Array Nat × Array Nat) := do
  let digest ← word bytes
  match sphincs_c10.wots.extract_digits digest with
  | .ok r => some ((r.val.map (·.val)).toArray,
      SphincsCVerify.Util.extractDigits (toSpecDigest digest))
  | _ => none

def digitAgrees (bytes : Array UInt8) (expected : Array Nat) : Bool :=
  match digitRun bytes with
  | some (a,b) => a == expected && b == expected &&
      a.toList.sum == SphincsCVerify.Util.digitSum b
  | none => false

def check : IO Unit := do
  unless hashVectors.length == 140 && digitVectors.length == 262 do
    throw (IO.userError "WOTS bridge corpus inventory changed")
  for (words, count, expected) in hashVectors do
    unless expected.size == 32 && hashAgrees words count expected do
      throw (IO.userError "WOTS hash Rust/extracted/verifier mismatch")
    for j in [0, 31] do
      if hashAgrees words count (expected.set! j (expected[j]! ^^^ 1)) then
        throw (IO.userError "WOTS hash changed-output control accepted")
  for (bytes, expected) in digitVectors do
    unless expected.size == 43 && digitAgrees bytes expected do
      throw (IO.userError "WOTS digits Rust/extracted/verifier mismatch")
    for j in [0, 42] do
      if digitAgrees bytes (expected.set! j (expected[j]! + 1)) then
        throw (IO.userError "WOTS digit changed-output control accepted")
  unless hashRun #[] 0 == none &&
      hashRun #[#[], #[], #[]] 0 == none &&
      hashRun (hashVectors.head!.1) (2^32) == none && digitRun #[] == none do
    throw (IO.userError "WOTS malformed input control accepted")
  IO.println "OK: 140 WOTS hash + 262 digit Rust/extracted/verifier cases; 804 changed-output and 4 malformed-input controls"

#eval check
end WotsBridgeDiff
