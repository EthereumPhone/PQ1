/- Executed corpus checks supplement the universal HMsgSpecBridge theorem.
   They test the supplied backend model against the host implementation on
   these inputs; they do not establish SHA backend equivalence for all inputs. -/
import Extracted.HMsgSpecBridge
import Extracted.HMsgDiffVectors
namespace HMsgDiff
open Aeneas Aeneas.Std Extracted.Equiv

def word (bs : Array UInt8) : Option (Std.Array Std.U8 32#usize) :=
  let l := bs.toList.map Sha256Pure.ofUInt8
  if h : l.length = 32 then some ⟨l, by simpa using h⟩ else none

def run (words : Array (Array UInt8)) : Option (Array UInt8 × Array UInt8) := do
  if words.size != 4 then none else do
    let seed ← word words[0]!
    let root ← word words[1]!
    let r ← word words[2]!
    let message ← word words[3]!
    match sphincs_c10.hash.h_msg seed root r message with
    | .ok d => some ((toSpecDigest d).data,
        (SphincsCVerify.Spec.hMsg (toSpecDigest seed) (toSpecDigest root)
          (toSpecDigest r) (toSpecDigest message)).data)
    | _ => none

def agreesWith (words : Array (Array UInt8)) (expected : Array UInt8) : Bool :=
  match run words with
  | some (a,b) => a == expected && b == expected
  | none => false

def check : IO Unit := do
  unless vectors.length == 132 do throw (IO.userError "H_msg vector inventory changed")
  for (words, expected) in vectors do
    unless expected.size == 32 && agreesWith words expected do
      throw (IO.userError "Rust / extracted / verifier H_msg mismatch")
    -- Full-width output: modifying either half of the expected digest fails.
    for j in [0, 31] do
      if agreesWith words (expected.set! j (expected[j]! ^^^ 1)) then
        throw (IO.userError "H_msg output mutation accepted")
  unless run #[] == none && run #[#[], #[], #[], #[]] == none do
    throw (IO.userError "H_msg wrong-width input accepted")
  IO.println "OK: 132 H_msg Rust/extracted/verifier vectors, 264 output controls, wrong widths"
#eval check
end HMsgDiff
