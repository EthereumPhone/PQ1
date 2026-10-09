/- Actual layer parsers and continuation versus the independent Rust byte oracle. -/
import Extracted.HypertreeStrictSpec
import Extracted.HypertreeDiffVectors
namespace HypertreeDiff
open Aeneas Aeneas.Std Extracted.Equiv SphincsCVerify.Spec

def hexDigit (c : Char) : Option Nat :=
  if '0' ≤ c && c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c && c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else none

def unhexList : List Char → Option (List Std.U8)
  | [] => some []
  | a :: b :: rest => do
    let x ← hexDigit a
    let y ← hexDigit b
    let tail ← unhexList rest
    some ((⟨BitVec.ofNat 8 (16*x+y)⟩ : Std.U8) :: tail)
  | _ => none

def bytes (n : Std.Usize) (s : String) : Option (Std.Array Std.U8 n) := do
  let l ← unhexList s.toList
  if h : l.length = n.val then some ⟨l, h⟩ else none

structure Outcome where
  result : _root_.Array UInt8
  ok0 : Bool
  ok1 : Bool
  count0 : Nat
  count1 : Nat
  accepted : Bool
  deriving BEq

def run (seed root sig current : String) (idx : Nat) : Option Outcome := do
  let s ← bytes 32#usize seed
  let r ← bytes 16#usize root
  let c ← bytes 16#usize current
  let signature ← bytes 4008#usize sig
  if idx ≥ 2^32 then none else do
    let i : Std.U32 := ⟨BitVec.ofNat 32 idx⟩
    for layer in ([⟨0, by decide⟩, ⟨1, by decide⟩] : List (Fin 2)) do
      let start : Std.Usize := ⟨BitVec.ofNat _ (2336+836*layer.val)⟩
      let authStart : Std.Usize := ⟨BitVec.ofNat _ (3028+836*layer.val)⟩
      match sphincs_c10.hypertree.verify_loop3_loop0 {start := 0#usize, «end» := 43#usize}
          signature start (Array.repeat 43#usize (Array.repeat 16#usize 0#u8)),
          sphincs_c10.hypertree.verify_loop3_loop1 {start := 0#usize, «end» := 9#usize}
          signature authStart (Array.repeat 9#usize (Array.repeat 16#usize 0#u8)) with
      | .ok (off, chains), .ok (off', auth) =>
        if off.val != 3024+836*layer.val || off'.val != 3172+836*layer.val ||
            chains.val != (parsedLayerChains signature layer).val ||
            auth.val != (parsedLayerAuth signature layer).val then none else pure ()
      | _, _ => none
    let l0 := toSpecLayer signature 0
    let l1 := toSpecLayer signature 1
    let w0 := Wots.pkFromSig (toSpecDigest s) 0 (UInt64.ofNat (idx/512))
      (UInt32.ofNat (idx%512)) (toSpecNode c) l0.wots
    let node0 := rawLayerRoot s signature 0 idx (toSpecNode c)
    let w1 := Wots.pkFromSig (toSpecDigest s) 1 (UInt64.ofNat (idx/512/512))
      (UInt32.ofNat (idx/512%512)) node0 l1.wots
    let raw := rawHypertreeRoot s signature idx (toSpecNode c)
    let strict := Hypertree.verifyHypertree (toSpecDigest s) (toSpecNode c) idx
      (parsedHypertreeLayers signature)
    if strict.isSome != (w0.isSome && w1.isSome) ||
        (strict.isSome && strict.map (·.data) != some raw.data) then none else do
      match sphincs_c10.hypertree.verify_loop3 {start := 0#u32, «end» := 2#u32}
          signature s 2336#usize c i, verifierHypertreeContinuation s r signature c i with
      | .ok (off, node), .ok accepted =>
        if off != 4008#usize || (toSpecNode node).data != raw.data ||
            accepted != (raw.data == (toSpecNode r).data) then none else
          some ⟨raw.data, w0.isSome, w1.isSome, l0.wots.count.toNat, l1.wots.count.toNat, accepted⟩
      | _, _ => none

def agrees (result : Option Outcome) (v : Vector) : Bool :=
  match result, bytes 16#usize v.result, bytes 16#usize v.root with
  | some r, some expected, some root =>
    r == (⟨(toSpecNode expected).data, v.ok0, v.ok1, v.count0, v.count1,
      (toSpecNode expected).data == (toSpecNode root).data⟩ : Outcome)
  | _, _, _ => false

def check : IO Unit := do
  unless vectors.length == 50 && (vectors.filter (fun v => v.ok0 && v.ok1)).length ≥ 4 &&
      (vectors.any (! ·.ok0)) && (vectors.any (! ·.ok1)) do
    throw (IO.userError "hypertree corpus inventory changed")
  for v in vectors do
    let result := run v.seed v.root v.sig v.current v.idx
    unless agrees result v do
      throw (IO.userError s!"hypertree execution disagreement: {v.label}")
    unless !(agrees result { v with ok0 := !v.ok0 }) &&
        !(agrees result { v with ok1 := !v.ok1 }) &&
        !(agrees result { v with count0 := v.count0 ^^^ 1 }) &&
        !(agrees result { v with count1 := v.count1 ^^^ 1 }) do
      throw (IO.userError "altered hypertree value accepted")
    unless !(agrees result { v with result := v.seed }) do
      throw (IO.userError "incorrect hypertree output width accepted")
    match result with
    | some r =>
      unless !(agrees (some {r with accepted := !r.accepted}) v) do
        throw (IO.userError "altered root comparison accepted")
      for j in [0,15] do
        if agrees (some {r with result := r.result.set! j (r.result[j]! ^^^ 1)}) v then
          throw (IO.userError "changed hypertree byte accepted")
    | none => throw (IO.userError "missing execution")
  let v := vectors.head!
  unless (run "" v.root v.sig v.current v.idx).isNone &&
      (run v.seed "" v.sig v.current v.idx).isNone &&
      (run v.seed v.root v.sig "" v.idx).isNone &&
      (run v.seed v.root "" v.current v.idx).isNone &&
      (run v.seed v.root (v.sig ++ "0") v.current v.idx).isNone &&
      (run v.seed v.root (v.sig ++ "00") v.current v.idx).isNone &&
      (run v.seed v.root ("gg" ++ v.sig) v.current v.idx).isNone &&
      (run v.seed v.root v.sig v.current (2^32)).isNone do
    throw (IO.userError "malformed hypertree input accepted")
  IO.println "OK: 50 actual parser/continuation/strict-spec executions; 350 value mutations, 50 output-width and 8 malformed-input controls"
#eval check
end HypertreeDiff
