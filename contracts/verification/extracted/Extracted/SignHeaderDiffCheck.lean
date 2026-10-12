/- Execute the actual extracted nonce/header against an independent Rust oracle. -/
import Extracted.SignHeaderSpec
import Extracted.SignHeaderDiffVectors

namespace SignHeaderDiff
open Aeneas Aeneas.Std Extracted.Equiv

def bytes (n : Std.Usize) (xs : _root_.Array UInt8) : Option (Std.Array Std.U8 n) :=
  if h : xs.size = n.val then
    some ⟨xs.toList.map (fun x => ⟨BitVec.ofNat 8 x.toNat⟩), by simpa using h⟩
  else none

def hexDigit (c : Char) : Option Nat :=
  if '0' ≤ c && c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c && c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else none

def unhex : List Char → Option (List UInt8)
  | [] => some []
  | a :: b :: rest => do
    let hi ← hexDigit a
    let lo ← hexDigit b
    let tail ← unhex rest
    some (UInt8.ofNat (16*hi+lo) :: tail)
  | _ => none

structure Output where
  seed : _root_.Array UInt8
  signature : _root_.Array UInt8
  digest : _root_.Array UInt8
  indices : _root_.Array Nat
  ht : Nat
  offset : Nat
  last : Nat
  left : Nat

def run (v : Vector) : Option Output := do
  let sk ← bytes 32#usize v.sk
  let seed ← bytes 16#usize v.seed
  let root ← bytes 16#usize v.root
  let msg ← bytes 32#usize v.message
  let opt ← match v.opt with
    | none => some none
    | some xs => (bytes 16#usize xs).map some
  match signerHead sk seed root msg opt (), sphincs_c10.fors.grind_r sk seed root msg opt with
  | .ok (s,sig,indices,ht,offset,last,left), .ok (_,digest) =>
    some ⟨(s.val.map (fun b => UInt8.ofNat b.val)).toArray,
      (sig.val.map (fun b => UInt8.ofNat b.val)).toArray,
      (digest.val.map (fun b => UInt8.ofNat b.val)).toArray,
      (indices.val.map (·.val)).toArray, ht.val, offset.val, last.val, left.val⟩
  | _, _ => none

def agrees (out : Output) (v : Vector) : Bool :=
  match unhex v.signature.toList with
  | none => false
  | some expected => expected.length == 4008 && v.seed.size == 16 &&
      v.digest.size == 32 && v.indices.size == 13 &&
      out.seed == v.seed ++ _root_.Array.replicate 16 0 &&
      out.signature == expected.toArray && out.digest == v.digest &&
      out.indices == v.indices && out.ht == v.ht &&
      out.offset == 16 && out.last == 12 && out.left == 0

def check : IO Unit := do
  unless vectors.length == 2 && (vectors[0]!).opt.isNone &&
      (vectors[1]!).opt.isSome && (vectors[0]!).nonce == 0 &&
      (vectors[1]!).nonce > 0 && vectors.all (fun v => v.nonce < 16) do
    throw (IO.userError "header OptRand/first-nonce inventory changed")
  for v in vectors do
    let some out := run v | throw (IO.userError "actual header did not return")
    unless agrees out v do throw (IO.userError "actual header/oracle mismatch")
    unless out.indices.all (· < 2048) && out.ht < 262144 do
      throw (IO.userError "header index bound failed")
    for j in [0,15,16,2335,2336,4007] do
      if agrees {out with signature := out.signature.set! j (out.signature[j]! ^^^ 1)} v then
        throw (IO.userError "altered header signature byte accepted")
    for j in [0,15,16,31] do
      if agrees {out with seed := out.seed.set! j (out.seed[j]! ^^^ 1)} v then
        throw (IO.userError "altered padded seed accepted")
    for j in [0,12] do
      if agrees {out with indices := out.indices.set! j (out.indices[j]! + 1)} v then
        throw (IO.userError "altered FORS index accepted")
    for changed in [{out with ht := out.ht + 1}, {out with offset := 15},
        {out with last := 11}, {out with left := 1},
        {out with digest := out.digest.set! 31 (out.digest[31]! ^^^ 1)}] do
      if agrees changed v then throw (IO.userError "altered header field accepted")
    for changed in [{v with signature := ""}, {v with signature := "zz"},
        {v with digest := #[]}, {v with indices := #[]}] do
      if agrees out changed then throw (IO.userError "malformed expected header accepted")
    for changed in [{v with sk := #[]}, {v with message := #[]},
        {v with seed := #[]}, {v with seed := v.seed.push 0},
        {v with root := #[]}, {v with root := v.root.push 0},
        {v with opt := some #[]}, {v with opt := some (v.seed.push 0)}] do
      unless (run changed).isNone do throw (IO.userError "malformed header input accepted")
    IO.println s!"PASS actual header: nonce {v.nonce}, ht {v.ht}"
  IO.println "OK: both actual nonce/header modes match independent full-byte and digest-field oracles; 34 altered-output, 8 expected-shape and 16 malformed-input controls"

#eval check
end SignHeaderDiff
