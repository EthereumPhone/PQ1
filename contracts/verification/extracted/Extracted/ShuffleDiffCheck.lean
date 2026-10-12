/- Exact order checks also pin the explicit SHA-block model boundary. -/
import Extracted.ShuffleSpec
import Extracted.ShuffleDiffVectors
namespace ShuffleDiff
open Aeneas Aeneas.Std

def run (v : Vector) : Option (_root_.Array UInt8) := do
  if h : v.seed.size = 32 then
    if v.n > 64 then none else do
      let seed : Std.Array Std.U8 32#usize :=
        ⟨v.seed.toList.map (fun b => ⟨BitVec.ofNat 8 b.toNat⟩), by simpa using h⟩
      match sphincs_c10.shuffle.fisher_yates seed (⟨BitVec.ofNat System.Platform.numBits v.n⟩ : Std.Usize) with
      | .ok r => some (r.val.map (fun b => UInt8.ofNat b.val)).toArray
      | _ => none
  else none

def check : IO Unit := do
  unless vectors.length == 72 do throw (IO.userError "shuffle corpus inventory changed")
  for v in vectors do
    unless v.n ≤ 64 && v.order.size == 64 do throw (IO.userError "malformed expected shuffle")
    let some got := run v | throw (IO.userError "shuffle failed")
    unless got == v.order do throw (IO.userError "shuffle stream/order disagreement")
    for i in [0,31,63] do
      let changed := v.order.set! i (v.order[i]! ^^^ 1)
      if got == changed then throw (IO.userError "changed prefix/tail accepted")
    for changed in [{v with seed := #[]}, {v with seed := v.seed.push 0}, {v with n := 65}] do
      unless (run changed).isNone do throw (IO.userError "malformed shuffle input accepted")
  IO.println "OK: 72 exact shuffle stream/order/tail witnesses, 216 altered outputs, 216 malformed inputs"
#eval check
end ShuffleDiff
