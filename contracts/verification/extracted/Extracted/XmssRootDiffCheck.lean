/- Both actual root entries and faithful references versus the Rust oracle.
   The internal pure tree is also executed on the public-root case; the
   full-width case's duplicate pure evaluation is allocated to the actual
   authentication builder in XmssAuthDiffCheck. Universal proofs cover both. -/
import Extracted.XmssRootBridge
import Extracted.XmssRootDiffVectors
namespace XmssRootDiff
open Aeneas Aeneas.Std Extracted.Equiv SphincsCVerify.Spec

def bytes (n : Std.Usize) (xs : _root_.Array UInt8) : Option (Std.Array Std.U8 n) :=
  if h : xs.size = n.val then
    some ⟨xs.toList.map (fun x => ⟨BitVec.ofNat 8 x.toNat⟩), by simpa using h⟩
  else none

def run (v : Vector) : Option (_root_.Array UInt8) := do
  let seed ← bytes 32#usize v.seed
  let sk ← bytes 32#usize v.sk
  if v.layer ≥ 2^32 || v.tree ≥ 2^64 || v.lo ≥ 256 || v.hi ≥ 256 then none else do
    if v.publicRoot && (v.layer != 1 || v.tree != 0 || v.lo != 0 || v.hi != 0 ||
        v.seed.extract 16 32 != _root_.Array.replicate 16 0) then none else do
      let layer : Std.U32 := ⟨BitVec.ofNat 32 v.layer⟩
      let tree : Std.U64 := ⟨BitVec.ofNat 64 v.tree⟩
      let lo : Std.U8 := ⟨BitVec.ofNat 8 v.lo⟩
      let hi : Std.U8 := ⟨BitVec.ofNat 8 v.hi⟩
      let actual ← if v.publicRoot then do
        let pkSeed ← bytes 16#usize (v.seed.extract 0 16)
        match sphincs_c10.hypertree.compute_pk_root sk pkSeed with
        | .ok result => some (toSpecNode result).data
        | _ => none
      else
        match sphincs_c10.merkle.compute_subtree_root seed sk layer tree () lo hi with
        | .ok result => some (toSpecNode result).data
        | _ => none
      if (v.publicRoot && actual != (toSpecNode (xmssRootNode seed sk layer tree 9 0)).data) ||
          actual != (mtNode (toSpecDigest seed) (UInt32.ofNat v.layer) (UInt64.ofNat v.tree)
            (fun j => Wots.keygenPk (toSpecDigest seed) (toSpecDigest sk)
              (UInt32.ofNat v.layer) (UInt64.ofNat v.tree) (UInt32.ofNat j)) 9 0).data then
        none else some actual

def agrees (result : Option (_root_.Array UInt8)) (v : Vector) : Bool :=
  v.result.size == 16 && result == some v.result

def check : IO Unit := do
  unless vectors.length == 2 && vectors.head!.publicRoot && !vectors[1]!.publicRoot do
    throw (IO.userError "XMSS root corpus inventory changed")
  for v in vectors do
    let result := run v
    unless agrees result v do throw (IO.userError "XMSS root disagreement")
    for j in [0,15] do
      if agrees result {v with result := v.result.set! j (v.result[j]! ^^^ 1)} then
        throw (IO.userError "altered XMSS root accepted")
    if agrees result {v with result := v.seed} then
      throw (IO.userError "wrong XMSS root width accepted")
  let v := vectors.head!
  for changed in [
      {v with seed := #[]}, {v with seed := v.seed.push 0},
      {v with sk := #[]}, {v with sk := v.sk.push 0},
      {v with layer := 2^32}, {v with tree := 2^64},
      {v with lo := 256}, {v with hi := 256},
      {v with seed := v.seed.set! 31 1}, {v with layer := 0}, {v with hi := 1}] do
    unless (run changed).isNone do throw (IO.userError "malformed XMSS root input accepted")
  IO.println "OK: 2 complete actual/vendored XMSS trees (public root and full-width subtree), public-root pure tree; independent Rust roots; 4 value, 2 width, 11 malformed controls"
#eval check
end XmssRootDiff
