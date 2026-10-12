/- Execute actual signing, recovery and keygen against independently generated
   byte witnesses. These bounded cases complement the universal proofs. -/
import Extracted.WotsSignSpec
import Extracted.WotsKeygenBridge
import Extracted.WotsSignDiffVectors

namespace WotsSignDiff
open Aeneas Aeneas.Std Extracted.Equiv

def bytes (n : Std.Usize) (xs : _root_.Array UInt8) : Option (Std.Array Std.U8 n) :=
  if h : xs.size = n.val then
    some ⟨xs.toList.map (fun x => ⟨BitVec.ofNat 8 x.toNat⟩), by simpa using h⟩
  else none

def chains (xs : _root_.Array (_root_.Array UInt8)) :
    Option (Std.Array (Std.Array Std.U8 16#usize) 43#usize) := do
  let rows ← xs.toList.mapM (bytes 16#usize)
  if h : rows.length = 43 then some ⟨rows, by simpa using h⟩ else none

structure Output where
  sigma : _root_.Array (_root_.Array UInt8)
  count : Nat
  recovered : _root_.Array UInt8
  pk : _root_.Array UInt8

def recover (v : Vector) (sigma : _root_.Array (_root_.Array UInt8))
    (count : Nat) : Option (_root_.Array UInt8) := do
  let seed ← bytes 32#usize v.seed
  let message ← bytes 16#usize v.message
  let sigma ← chains sigma
  if v.layer ≥ 2^32 || v.tree ≥ 2^64 || v.kp ≥ 2^32 || count ≥ 2^32 then none else do
    match sphincs_c10.wots.pk_from_sig seed ⟨BitVec.ofNat 32 v.layer⟩
        ⟨BitVec.ofNat 64 v.tree⟩ ⟨BitVec.ofNat 32 v.kp⟩ message sigma ⟨BitVec.ofNat 32 count⟩ with
    | .ok node => some (toSpecNode node).data
    | _ => none

def run (v : Vector) : Option Output := do
  let seed ← bytes 32#usize v.seed
  let sk ← bytes 32#usize v.sk
  let message ← bytes 16#usize v.message
  let shuffle ← bytes 32#usize v.shuffle
  if v.layer ≥ 2^32 || v.tree ≥ 2^64 || v.kp ≥ 2^32 then none else do
    let layer : Std.U32 := ⟨BitVec.ofNat 32 v.layer⟩
    let tree : Std.U64 := ⟨BitVec.ofNat 64 v.tree⟩
    let kp : Std.U32 := ⟨BitVec.ofNat 32 v.kp⟩
    let (sigma, count) ← match sphincs_c10.wots.sign_with_shuffle seed sk layer tree kp message shuffle () 255#u8 with
      | .ok result => some result
      | _ => none
    let pk ← match sphincs_c10.wots.keygen_pk seed sk layer tree kp with
      | .ok result => some (toSpecNode result).data
      | _ => none
    let rows := (sigma.val.map (fun row => (toSpecNode row).data)).toArray
    let recovered ← recover v rows count.val
    some ⟨rows, count.val, recovered, pk⟩

def agrees (out : Output) (v : Vector) : Bool :=
  v.count < 10000000 && v.sigma.size == 43 && v.sigma.all (fun row => row.size == 16) &&
  v.pk.size == 16 && out.sigma == v.sigma && out.count == v.count && out.pk == v.pk && out.recovered == v.pk

def check : IO Unit := do
  unless vectors.length == 3 && (vectors.map (·.count)).all (· < 64) &&
      vectors.head!.count == 0 && (vectors.drop 1).all (fun v => v.count > 0) do
    throw (IO.userError "WOTS sign witness inventory changed")
  for v in vectors do
    let some out := run v | throw (IO.userError "actual WOTS signing failed")
    unless agrees out v do throw (IO.userError "WOTS signing/oracle disagreement")
    let some alternate := run {v with shuffle := _root_.Array.replicate 32 0x81}
      | throw (IO.userError "alternate shuffled signer failed")
    unless agrees alternate v do throw (IO.userError "shuffle changed the signature")
    for i in [0,21,42] do
      let row := v.sigma[i]!
      let changed := v.sigma.set! i (row.set! 0 (row[0]! ^^^ 1))
      if agrees out {v with sigma := changed} then throw (IO.userError "altered signature accepted")
      let some recovered := recover v changed v.count | throw (IO.userError "changed signature recovery failed")
      unless recovered != v.pk do throw (IO.userError "altered chain recovered the key")
    for changed in [
        {v with count := v.count + 1}, {v with count := 10000000},
        {v with pk := #[]}, {v with sigma := #[]},
        {v with sigma := v.sigma.extract 0 42}, {v with sigma := v.sigma.push v.pk},
        {v with sigma := v.sigma.set! 0 v.seed}] do
      if agrees out changed then throw (IO.userError "wrong signature count or shape accepted")
    for changed in [
        {v with seed := #[]}, {v with sk := #[]}, {v with message := v.seed},
        {v with shuffle := #[]}, {v with layer := 2^32},
        {v with tree := 2^64}, {v with kp := 2^32}] do
      unless (run changed).isNone do throw (IO.userError "malformed signer input accepted")
  IO.println "OK: three actual WOTS signatures/recoveries/keygens, alternate shuffles, first-count/both digit endpoints/full-width witnesses; altered chains/counts/shapes/inputs rejected"
#eval check
end WotsSignDiff
