import Extracted.Sha256Portable.Compression
import Extracted.Sha256Portable.DiffVectors

open Aeneas Aeneas.Std
open SphincsCVerify.Spec.Sha256Impl

namespace Sha256PortableDiff

def words (n : Std.Usize) (xs : _root_.Array UInt32) : Option (Std.Array Std.U32 n) :=
  let values := xs.toList.map (fun x => (⟨BitVec.ofNat 32 x.toNat⟩ : Std.U32))
  if h : values.length = n.val then some ⟨values, h⟩ else none

def run (state block : _root_.Array UInt32) :
    Option (_root_.Array Word × _root_.Array Word) := do
  let s ← words 8#usize state
  let b ← words 16#usize block
  match sha256_portable.soft.sha256_digest_block_u32 s b with
  | .ok result => some (Sha256Portable.toWords result,
      compress (Sha256Portable.toWords s) (Sha256Portable.toWords b))
  | _ => none

def agrees (state block expected : _root_.Array UInt32) : Bool :=
  match run state block with
  | some (actual, spec) =>
    let wanted := expected.map (fun x => BitVec.ofNat 32 x.toNat)
    actual == wanted && spec == wanted
  | none => false

def check : IO Unit := do
  unless vectors.length == 112 do throw (IO.userError "word corpus inventory changed")
  for (state, block, expected) in vectors do
    unless expected.size == 8 && agrees state block expected do
      throw (IO.userError "Rust / extracted / specification word-compression mismatch")
    for index in [0:8] do
      if agrees state block (expected.set! index (expected[index]! ^^^ 1)) then
        throw (IO.userError "changed word-compression output accepted")
  unless run #[] #[] == none &&
      run (Array.replicate 8 0) (Array.replicate 15 0) == none &&
      run (Array.replicate 9 0) (Array.replicate 16 0) == none do
    throw (IO.userError "word-compression wrong-width input accepted")
  IO.println "OK: 112 Rust/extracted/spec cases, 896 output mutations and wrong-width controls"

#eval check
end Sha256PortableDiff
