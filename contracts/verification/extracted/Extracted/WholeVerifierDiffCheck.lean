/- Complete decoder and verifier execution against independent Rust byte fixtures. -/
import Extracted.WholeVerifierSpec
import Extracted.WholeVerifierDiffVectors
namespace WholeVerifierDiff
open Aeneas Aeneas.Std Extracted.Equiv SphincsCVerify.Spec SphincsCVerify.Util

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
  digest : _root_.Array UInt8
  lastField : Nat
  actual : Bool
  raw : Bool
  strict : Bool
  deriving BEq

def sameSignature (a b : Hypertree.Signature) : Bool :=
  a.r.data == b.r.data &&
  a.fors.secrets.map (·.data) == b.fors.secrets.map (·.data) &&
  a.fors.authPaths.map (fun xs => xs.map (·.data)) ==
    b.fors.authPaths.map (fun xs => xs.map (·.data)) &&
  a.layers.map (fun l => (l.wots.chains.map (·.data), l.wots.count,
    l.authPath.map (·.data))) ==
  b.layers.map (fun l => (l.wots.chains.map (·.data), l.wots.count,
    l.authPath.map (·.data)))

def run (seed root msg sig : String) : Option Outcome := do
  let s ← bytes 16#usize seed
  let r ← bytes 16#usize root
  let m ← bytes 32#usize msg
  let signature ← bytes 4008#usize sig
  let decoded := Signature.deserialise (toSpecSignatureBytes signature)
  if !sameSignature decoded (parsedSignature signature) then none else do
    let digest := toSpecDigest (verifierDigest s r m signature)
    match sphincs_c10.hypertree.verify s r m signature with
    | .ok actual => some ⟨digest.data, (extractForsIndices digest).getD 12 0,
        actual, rawVerifierResult s r m signature,
        Signature.verify ⟨toSpecNode s, toSpecNode r⟩ (toSpecDigest m)
          (toSpecSignatureBytes signature)⟩
    | _ => none

def agrees (result : Option Outcome) (v : Vector) : Bool :=
  match result, bytes 32#usize v.digest with
  | some r, some digest =>
    r == (⟨(toSpecDigest digest).data, v.lastField, v.actual, v.actual, v.strict⟩ : Outcome)
  | _, _ => false

def check : IO Unit := do
  unless vectors.length == 48 && (vectors.filter (·.strict)).length ≥ 4 &&
      (vectors.any (fun v => v.lastField != 0)) &&
      (vectors.any (fun v => v.lastField == 0 && !v.strict)) do
    throw (IO.userError "whole verifier corpus inventory changed")
  for v in vectors do
    let result := run v.seed v.root v.msg v.sig
    unless agrees result v do
      throw (IO.userError s!"whole verifier execution disagreement: {v.label}")
    unless !(agrees result {v with lastField := v.lastField ^^^ 1}) do
      throw (IO.userError "altered final FORS field accepted")
    unless !(agrees result {v with digest := v.seed}) do
      throw (IO.userError "incorrect digest output width accepted")
    match result with
    | some r =>
      unless !(agrees (some {r with actual := !r.actual}) v) &&
          !(agrees (some {r with raw := !r.raw}) v) &&
          !(agrees (some {r with strict := !r.strict}) v) do
        throw (IO.userError "altered verifier decision accepted")
      for j in [0,31] do
        if agrees (some {r with digest := r.digest.set! j (r.digest[j]! ^^^ 1)}) v then
          throw (IO.userError "altered digest byte accepted")
    | none => throw (IO.userError "missing whole verifier execution")
  let v := vectors.head!
  unless (run "" v.root v.msg v.sig).isNone &&
      (run v.seed "" v.msg v.sig).isNone &&
      (run v.seed v.root "" v.sig).isNone &&
      (run v.seed v.root v.msg "").isNone &&
      (run v.seed v.root v.msg (v.sig ++ "0")).isNone &&
      (run v.seed v.root v.msg (v.sig ++ "00")).isNone &&
      (run v.seed v.root v.msg ("gg" ++ v.sig)).isNone do
    throw (IO.userError "malformed whole verifier input accepted")
  IO.println "OK: 48 full decoder/actual/raw/strict verifier executions; 288 value mutations, 48 output-width and 7 malformed-input controls"
#eval check
end WholeVerifierDiff
