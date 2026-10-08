/- Executed Rust/extracted/verifier checks, including the explicit none/zero
   distinction. These supplement the universal recovery refinement. -/
import Extracted.WotsRecoveryBridge
import Extracted.WotsRecoveryDiffVectors

namespace WotsRecoveryDiff
open Aeneas Aeneas.Std Extracted.Equiv

def word (bs : _root_.Array UInt8) : Option (Std.Array Std.U8 32#usize) :=
  let l := bs.toList.map Sha256Pure.ofUInt8
  if h : l.length = 32 then some ⟨l, by simpa using h⟩ else none

def node (bs : _root_.Array UInt8) : Option (Std.Array Std.U8 16#usize) :=
  let l := bs.toList.map Sha256Pure.ofUInt8
  if h : l.length = 16 then some ⟨l, by simpa using h⟩ else none

def signature (bs : _root_.Array (_root_.Array UInt8)) :
    Option (Std.Array (Std.Array Std.U8 16#usize) 43#usize) := do
  let l ← bs.toList.mapM node
  if h : l.length = 43 then some ⟨l, by simpa using h⟩ else none

def recoveryRun (seedBytes : _root_.Array UInt8) (layer tree kp : Nat)
    (message : _root_.Array UInt8) (count : Nat) (chains : _root_.Array (_root_.Array UInt8)) :
    Option (_root_.Array UInt8 × Option (_root_.Array UInt8)) := do
  if layer ≥ 2^32 || tree ≥ 2^64 || kp ≥ 2^32 || count ≥ 2^32 then none else do
    let s ← word seedBytes
    let m ← node message
    let sig ← signature chains
    let l : Std.U32 := ⟨BitVec.ofNat 32 layer⟩
    let t : Std.U64 := ⟨BitVec.ofNat 64 tree⟩
    let k : Std.U32 := ⟨BitVec.ofNat 32 kp⟩
    let c : Std.U32 := ⟨BitVec.ofNat 32 count⟩
    match sphincs_c10.wots.pk_from_sig s l t k m sig c with
    | .ok r => some ((toSpecNode r).data,
        (SphincsCVerify.Spec.Wots.pkFromSig (toSpecDigest s)
          (UInt32.ofNat layer) (UInt64.ofNat tree) (UInt32.ofNat kp)
          (toSpecNode m) (toSpecSigma sig c)).map (·.data))
    | _ => none

def recoveryAgrees (result : Option (_root_.Array UInt8 × Option (_root_.Array UInt8)))
    (accepted : Bool) (expected : _root_.Array UInt8) : Bool :=
  match result with
  | some (actual, specification) =>
    actual == expected &&
      specification == (if accepted then some expected else none) &&
      (accepted || actual == _root_.Array.replicate 16 0)
  | none => false

def chainRun (start steps : Nat) : Option (_root_.Array UInt8 × _root_.Array UInt8) := do
  if start ≥ 2^32 || steps ≥ 2^32 || start + steps ≥ 2^32 then none else do
    let s ← word seed
    let a ← word chainAdrs
    let x ← node nodes[42]!
    match sphincs_c10.hash.chain_hash s a x ⟨BitVec.ofNat 32 start⟩ ⟨BitVec.ofNat 32 steps⟩ with
    | .ok r => some ((toSpecNode r).data,
        (SphincsCVerify.Spec.chainHash (toSpecDigest s) (toSpecDigest a)
          (toSpecNode x) start steps).data)
    | _ => none

def compressionRun (n : Nat) : Option (_root_.Array UInt8 × _root_.Array UInt8) := do
  if n > 43 then none else do
    let s ← word seed
    let a ← word chainAdrs
    let sig ← signature nodes
    let vals : Slice (Std.Array Std.U8 16#usize) := ⟨sig.val.take n, by
      have h : sig.val.length = 43 := by simpa using sig.property
      simp [List.length_take, h]; scalar_tac⟩
    match sphincs_c10.hash.th_multi s a vals with
    | .ok r => some ((toSpecNode r).data,
        (SphincsCVerify.Spec.thMulti (toSpecDigest s) (toSpecDigest a)
          (vals.val.map toSpecNode)).data)
    | _ => none

def pairAgrees (result : Option (_root_.Array UInt8 × _root_.Array UInt8))
    (expected : _root_.Array UInt8) : Bool :=
  match result with
  | some (a,b) => a == expected && b == expected
  | none => false

def check : IO Unit := do
  unless recoveryVectors.length == 20 && chainVectors.length == 40 && compressionVectors.length == 4 do
    throw (IO.userError "WOTS recovery corpus inventory changed")
  for (l,t,k,m,c,accepted,expected) in recoveryVectors do
    let result := recoveryRun seed l t k m c nodes
    unless expected.size == 16 && recoveryAgrees result accepted expected do
      throw (IO.userError "WOTS recovery Rust/extracted/verifier mismatch")
    if recoveryAgrees result (!accepted) expected then
      throw (IO.userError "WOTS recovery outcome control accepted")
    for j in [0,15] do
      if recoveryAgrees result accepted (expected.set! j (expected[j]! ^^^ 1)) then
        throw (IO.userError "WOTS recovery changed-output control accepted")
  for (start,steps,expected) in chainVectors do
    let result := chainRun start steps
    unless expected.size == 16 && pairAgrees result expected do
      throw (IO.userError "WOTS chain Rust/extracted/verifier mismatch")
    for j in [0,15] do
      if pairAgrees result (expected.set! j (expected[j]! ^^^ 1)) then
        throw (IO.userError "WOTS chain changed-output control accepted")
  for (n,expected) in compressionVectors do
    let result := compressionRun n
    unless expected.size == 16 && pairAgrees result expected do
      throw (IO.userError "WOTS compression Rust/extracted/verifier mismatch")
    for j in [0,15] do
      if pairAgrees result (expected.set! j (expected[j]! ^^^ 1)) then
        throw (IO.userError "WOTS compression changed-output control accepted")
  let (l,t,k,m,c,_,_) := recoveryVectors.head!
  unless recoveryRun #[] l t k m c nodes == none &&
      recoveryRun seed l t k #[] c nodes == none &&
      recoveryRun seed l t k m c #[] == none &&
      recoveryRun seed l t k m (2^32) nodes == none &&
      recoveryRun seed (2^32) t k m c nodes == none &&
      recoveryRun seed l (2^64) k m c nodes == none &&
      recoveryRun seed l t (2^32) m c nodes == none &&
      chainRun (2^32-1) 1 == none && compressionRun 44 == none do
    throw (IO.userError "WOTS recovery malformed input control accepted")
  IO.println "OK: 20 recovery + 40 chain + 4 compression Rust/extracted/verifier cases; 148 altered-output/outcome and 9 malformed-input controls"

#eval check
end WotsRecoveryDiff
