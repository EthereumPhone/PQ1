/- The strict verifier agrees when it returns a node. Its `none` branch is
   deliberately not identified with Rust's zero-sentinel continuation. -/
import Extracted.HypertreeContinuationSpec
import Extracted.HypertreeContinuationVendored
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10 SphincsCVerify.Spec
set_option maxHeartbeats 4000000
set_option maxRecDepth 8192

def toSpecLayer (sig : C10Signature) (layer : Fin 2) : Hypertree.LayerSig :=
  { wots := toSpecSigma (parsedLayerChains sig layer) (parsedLayerCount sig layer)
    authPath := ((parsedLayerAuth sig layer).val.map toSpecNode).toArray
    authPathLen := by simp [SubtreeH, (parsedLayerAuth sig layer).property] }

def parsedHypertreeLayers (sig : C10Signature) : _root_.Array Hypertree.LayerSig :=
  #[toSpecLayer sig ⟨0, by decide⟩, toSpecLayer sig ⟨1, by decide⟩]

attribute [local irreducible] Wots.pkFromSig Hypertree.verifyAuthPath

/-- A successful strict-verifier reconstruction has exactly the actual
    continuation's root. No assertion about strict rejection is made here. -/
theorem strict_hypertree_success_eq_raw (seed : Std.Array Std.U8 32#usize)
    (sig : C10Signature) (current expected : ByteVec 16) (idx : Nat)
    (h : Hypertree.verifyHypertree (toSpecDigest seed) current idx
      (parsedHypertreeLayers sig) = some expected) :
    expected = rawHypertreeRoot seed sig idx current := by
  have hmask (n : Nat) : n &&& 511 = n % 512 := Nat.and_two_pow_sub_one_eq_mod n 9
  unfold Hypertree.verifyHypertree at h
  simp [hmask, D, SubtreeH, parsedHypertreeLayers, toSpecLayer,
    Std.Legacy.Range.forIn_eq_forIn_range', List.range', List.forIn_cons, List.forIn_nil,
    Id.run, Bind.bind, Pure.pure, Nat.shiftRight_eq_div_pow] at h
  cases h0 : Wots.pkFromSig (toSpecDigest seed) 0 (UInt64.ofNat (idx / 512))
      (UInt32.ofNat (idx % 512)) current
      (toSpecSigma (parsedLayerChains sig 0) (parsedLayerCount sig 0)) with
  | none => simp [h0] at h
  | some pk0 =>
    simp only [h0, Bool.false_eq_true, ↓reduceIte] at h
    cases h1 : Wots.pkFromSig (toSpecDigest seed) 1 (UInt64.ofNat (idx / 512 / 512))
        (UInt32.ofNat (idx / 512 % 512))
        (Hypertree.verifyAuthPath (toSpecDigest seed) 0 (UInt64.ofNat (idx / 512)) pk0 (idx % 512)
          ((parsedLayerAuth sig 0).val.map toSpecNode).toArray)
        (toSpecSigma (parsedLayerChains sig 1) (parsedLayerCount sig 1)) with
    | none => simp [h1] at h
    | some pk1 =>
      simp only [h1, Bool.false_eq_true, ↓reduceIte, Option.some.injEq] at h
      subst expected
      simp [rawHypertreeRoot, rawLayerRoot, h0, h1]

/-- A strict successful root determines the actual caller's Boolean result. -/
theorem firmware_continuation_matches_strict_success
    (seed : Std.Array Std.U8 32#usize) (root current : Std.Array Std.U8 16#usize)
    (sig : C10Signature) (idx : Std.U32) (expected : ByteVec 16)
    (h : Hypertree.verifyHypertree (toSpecDigest seed) (toSpecNode current) idx.val
      (parsedHypertreeLayers sig) = some expected) :
    verifierHypertreeContinuation seed root sig current idx
      ⦃ r => r = decide (expected = toSpecNode root) ⦄ := by
  rw [strict_hypertree_success_eq_raw seed sig (toSpecNode current) expected idx.val h]
  exact firmware_verifier_hypertree_continuation seed root current sig idx

end Extracted.Equiv
