/- Execute the full actual verifier, its prefix/continuation split and the
   faithful FORS specification on production Rust outputs. -/
import Extracted.ForsVerifierPrefix
import Extracted.ForsPrefixDiffVectors
namespace ForsPrefixDiff
open Aeneas Aeneas.Std Extracted.Equiv

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
  ht : Nat
  pk : _root_.Array UInt8
  accepted : Bool
  deriving BEq

def run (seed root msg sig : String) : Option Outcome := do
  let s ← bytes 16#usize seed
  let r ← bytes 16#usize root
  let m ← bytes 32#usize msg
  let signature ← bytes 4008#usize sig
  match verifierHead s r m signature with
  | .ok (padded, indices, ht, off) =>
    if off != 16#usize || indices.val[12]!.val != 0 then none else do
      match sphincs_c10.hypertree.verify_loop0 { start := 0#usize, «end» := 13#usize }
          signature off (Array.repeat 13#usize (Array.repeat 16#usize 0#u8)) with
      | .ok (off1, secrets) =>
        if off1 != 224#usize || secrets.val != (parsedForsSecrets signature).val then none else do
          match sphincs_c10.hypertree.verify_loop1 { start := 0#usize, «end» := 12#usize }
              signature off1 (Array.repeat 12#usize (Array.repeat 11#usize (Array.repeat 16#usize 0#u8))) with
          | .ok (off2, paths) =>
            if off2 != 2336#usize || paths.val != (parsedForsAuth signature).val then none else do
              let digest := verifierDigest s r m signature
              match forsForestPhase padded ht indices secrets paths with
              | .ok pk =>
                let specification := SphincsCVerify.Spec.Fors.reconstructForsPk
                  (toSpecDigest padded) (toSpecDigest digest) (toSpecForsSig secrets paths)
                if specification.map (·.data) != some (toSpecNode pk).data then none else do
                  match sphincs_c10.hypertree.verify s r m signature,
                      verifierHypertreeContinuation padded r signature pk ht with
                  | .ok actual, .ok tail =>
                    if actual != tail then none else
                      some ⟨(toSpecDigest digest).data, ht.val, (toSpecNode pk).data, actual⟩
                  | _, _ => none
              | _ => none
          | _ => none
      | _ => none
  | _ => none

def agrees (result : Option Outcome) (digest pk : String) (ht : Nat) (accepted : Bool) : Bool :=
  match result, bytes 32#usize digest, bytes 16#usize pk with
  | some r, some d, some p => r == (⟨(toSpecDigest d).data, ht, (toSpecNode p).data, accepted⟩ : Outcome)
  | _, _, _ => false

def check : IO Unit := do
  unless vectors.length == 22 && (vectors.filter (·.accepted)).length == 4 do
    throw (IO.userError "FORS prefix corpus inventory changed")
  for v in vectors do
    let result := run v.seed v.root v.msg v.sig
    unless agrees result v.digest v.pk v.ht v.accepted do
      throw (IO.userError s!"FORS prefix/full-verifier disagreement: {v.label}")
    unless !(agrees result v.digest v.pk (v.ht ^^^ 1) v.accepted) &&
        !(agrees result v.digest v.pk v.ht (!v.accepted)) do
      throw (IO.userError "altered prefix value accepted")
    -- Exchanging these fields tests their distinct 16/32-byte widths.
    unless !(agrees result v.pk v.pk v.ht v.accepted) &&
        !(agrees result v.digest v.digest v.ht v.accepted) do
      throw (IO.userError "incorrect prefix output width accepted")
    match result with
    | some r =>
      for j in [0,15] do
        let bad := { r with pk := r.pk.set! j (r.pk[j]! ^^^ 1) }
        if agrees (some bad) v.digest v.pk v.ht v.accepted then
          throw (IO.userError "changed FORS byte accepted")
      for j in [0,31] do
        let bad := { r with digest := r.digest.set! j (r.digest[j]! ^^^ 1) }
        if agrees (some bad) v.digest v.pk v.ht v.accepted then
          throw (IO.userError "changed digest byte accepted")
    | none => throw (IO.userError "missing execution")
  let v := vectors.head!
  unless (run "" v.root v.msg v.sig).isNone &&
      (run v.seed "" v.msg v.sig).isNone &&
      (run v.seed v.root "" v.sig).isNone &&
      (run v.seed v.root v.msg "").isNone &&
      (run v.seed v.root v.msg (v.sig ++ "0")).isNone &&
      (run v.seed v.root v.msg (v.sig ++ "00")).isNone &&
      (run v.seed v.root v.msg ("gg" ++ v.sig)).isNone do
    throw (IO.userError "malformed prefix input accepted")
  IO.println "OK: 22 full-verifier/prefix/specification executions (4 accepting); 132 value mutations, 44 output-width and 7 malformed-input controls"
#eval check
end ForsPrefixDiff
