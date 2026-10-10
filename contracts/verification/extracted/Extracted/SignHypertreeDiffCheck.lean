/- Execute both actual extracted signer iterations against the Rust byte oracle. -/
import Extracted.SignHypertreeCaller
import Extracted.SignHypertreeDiffVectors

namespace SignHypertreeDiff
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

def initial (pattern : Nat) : Std.Array Std.U8 4008#usize :=
  ⟨(List.range 4008).map (fun i => ⟨BitVec.ofNat 8 (17*i+29*(i/16)+43*pattern)⟩), by simp⟩

structure Output where
  signature : _root_.Array UInt8
  offset : Nat
  root : _root_.Array UInt8
  counts : _root_.Array Nat

def run (v : Vector) : Option Output := do
  let seed ← bytes 32#usize v.seed
  let sk ← bytes 32#usize v.sk
  let current ← bytes 16#usize v.current
  let shuffle ← bytes 32#usize v.shuffle
  if v.index ≥ 2^32 then none else do
    let idx : Std.U32 := ⟨BitVec.ofNat 32 v.index⟩
    match sphincs_c10.hypertree.sign_inner_loop3 {start := 0#u32, «end» := 2#u32}
        sk () shuffle seed (initial v.pattern) 2336#usize current idx with
    | .ok (sig,off,node) => some ⟨(sig.val.map (fun b => UInt8.ofNat b.val)).toArray,
        off.val, (toSpecNode node).data,
        #[(parsedLayerCount sig ⟨0,by decide⟩).val,(parsedLayerCount sig ⟨1,by decide⟩).val]⟩
    | _ => none

def agrees (out : Output) (v : Vector) : Bool :=
  match unhex v.signature.toList with
  | none => false
  | some expected => expected.length == 4008 && v.root.size == 16 && v.counts.size == 2 &&
      out.signature == expected.toArray && out.offset == 4008 && out.root == v.root && out.counts == v.counts

def check : IO Unit := do
  unless vectors.length == 3 && (vectors[0]!).index == 262143 &&
      (vectors[1]!).index == 4294967295 && (vectors[2]!).index == 4294967294 &&
      (vectors[2]!).index % 512 != ((vectors[2]!).index / 512) % 512 && vectors.all (fun v => v.counts.all (· < 64)) do
    throw (IO.userError "two-layer corpus boundary/mixed-leaf inventory changed")
  -- All three are checked in normal/extraction Rust. One full-width case executes
  -- both expensive actual Lean trees; universal proofs cover every index.
  for v in vectors.drop 2 do
    let some out := run v | throw (IO.userError "actual signer loop did not return")
    unless agrees out v do throw (IO.userError "two-layer signer/oracle mismatch")
    IO.println s!"PASS actual two-layer signer index {v.index}"
    let before := initial v.pattern
    for j in [:2336] do
      unless out.signature[j]! == UInt8.ofNat (before.val[j]!).val do
        throw (IO.userError "signer changed nonce/FORS prefix")
    for j in [0,15,16,223,224,2335,2336,3024,3027,3171,3172,3860,3863,4007] do
      if agrees {out with signature := out.signature.set! j (out.signature[j]! ^^^ 1)} v then
        throw (IO.userError "altered output byte accepted")
    for j in [0,15] do
      if agrees {out with root := out.root.set! j (out.root[j]! ^^^ 1)} v then
        throw (IO.userError "altered top root accepted")
    if agrees {out with offset := 4007} v || agrees {out with counts := #[0,0]} v then
      throw (IO.userError "altered offset/count accepted")
    for changed in [{v with signature := ""}, {v with signature := "zz"},
        {v with root := #[]}, {v with counts := #[]}] do
      if agrees out changed then throw (IO.userError "malformed expected output accepted")
    for changed in [{v with seed := #[]}, {v with seed := v.seed.push 0},
        {v with sk := #[]}, {v with current := #[]}, {v with current := v.current.push 0},
        {v with shuffle := #[]}, {v with shuffle := v.shuffle.push 0}, {v with index := 2^32}] do
      unless (run changed).isNone do throw (IO.userError "malformed signer input accepted")
  IO.println "OK: one actual full-width mixed-leaf two-layer signer loop matches independent full-byte/root/count oracles; all prefix bytes preserved; 18 altered-output, 4 output-shape and 8 malformed-input controls"

#eval check
end SignHypertreeDiff
