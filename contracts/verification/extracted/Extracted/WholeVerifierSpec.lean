/- Compose actual byte parsing, FORS, both layers and the final decision. -/
import Extracted.SignatureDecodeSpec
import Extracted.HMsgSpecBridge
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10 SphincsCVerify.Spec SphincsCVerify.Util
set_option maxHeartbeats 1000000
set_option maxRecDepth 8192

/-- A total executable model of the existing Rust verifier. WOTS rejection
    contributes a zero node before the XMSS walk, exactly as in Rust. -/
def rawVerifierResult (seed root : Std.Array Std.U8 16#usize)
    (msg : Std.Array Std.U8 32#usize) (sig : C10Signature) : Bool :=
  let digest := toSpecDigest (verifierDigest seed root msg sig)
  if (extractForsIndices digest).getD 12 0 ≠ 0 then false else
  match Fors.reconstructForsPk (toSpecDigest (pad16Pure seed)) digest (parsedSignature sig).fors with
  | none => false
  | some pk => decide (rawHypertreeRoot (pad16Pure seed) sig (extractHtIndex digest) pk = toSpecNode root)

attribute [local irreducible] Fors.reconstructForsPk rawHypertreeRoot

theorem final_fors_field (digest : Std.Array Std.U8 32#usize) :
    (extractForsIndices (toSpecDigest digest)).getD 12 0 =
      (digestWord digest >>> 132) % 2^11 := by
  unfold extractForsIndices
  rw [_root_.Array.getD_eq_getD_getElem?, _root_.Array.getElem?_ofFn,
    dif_pos (show 12 < K from by decide), Option.getD_some,
    vendored_readBitsLe_eq_digestWord digest _ _ (by simp only [A]; decide)]
  rfl

/-- The whole actual verifier terminates and agrees with the raw model on
    every represented input, without an acceptance or valid-signature premise. -/
theorem firmware_verify_raw_result (seed root : Std.Array Std.U8 16#usize)
    (msg : Std.Array Std.U8 32#usize) (sig : C10Signature) :
    hypertree.verify seed root msg sig ⦃ r => r = rawVerifierResult seed root msg sig ⦄ := by
  by_cases hz : (extractForsIndices (toSpecDigest (verifierDigest seed root msg sig))).getD 12 0 = 0
  · obtain ⟨pk, ht, hht, hfors, hcall⟩ := firmware_verify_fors_prefix seed root msg sig hz
    rw [hcall]
    simpa only [rawVerifierResult, parsedSignature, hz, ne_eq, not_true_eq_false,
      if_false, hfors, hht] using firmware_verifier_hypertree_continuation (pad16Pure seed) root pk sig ht
  · have hbad : (digestWord (verifierDigest seed root msg sig) >>> 132) % 2^11 ≠ 0 := by
      rwa [final_fors_field] at hz
    simpa only [rawVerifierResult, if_pos hz] using
      firmware_verify_rejects_nonzero_fors seed root msg sig hbad

/-- The actual header digest has exactly the complete verifier specification's
    padded seed/root/randomizer and message binding. -/
theorem verifierDigest_matches_spec (seed root : Std.Array Std.U8 16#usize)
    (msg : Std.Array Std.U8 32#usize) (sig : C10Signature) :
    toSpecDigest (verifierDigest seed root msg sig) =
      hMsg (ByteVec.pad16 (toSpecNode seed)) (ByteVec.pad16 (toSpecNode root))
        (ByteVec.pad16 (parsedSignature sig).r) (toSpecDigest msg) := by
  have h := firmware_h_msg_matches_vendored (pad16Pure seed) (pad16Pure root)
    (pad16Pure (verifierRandomizer sig)) msg
  simpa only [hash.h_msg_spec, WP.spec_ok, verifierDigest, recovery_pad, parsedSignature] using h

def strictVerifierResult (seed root : Std.Array Std.U8 16#usize)
    (msg : Std.Array Std.U8 32#usize) (sig : C10Signature) : Bool :=
  Hypertree.verifyWithDigest (toSpecDigest (pad16Pure seed)) (toSpecNode root)
    (toSpecDigest (verifierDigest seed root msg sig)) (parsedSignature sig)

/-- This binds the faithful byte-level entry point, including its real decoder
    and H_msg construction, to the same fields used in the Rust proof. -/
theorem byteVerifier_eq_strictResult (seed root : Std.Array Std.U8 16#usize)
    (msg : Std.Array Std.U8 32#usize) (sig : C10Signature) :
    Signature.verify ⟨toSpecNode seed, toSpecNode root⟩ (toSpecDigest msg)
      (toSpecSignatureBytes sig) = strictVerifierResult seed root msg sig := by
  simp only [Signature.verify, deserialise_matches_parsedSignature, Hypertree.verify]
  rw [← verifierDigest_matches_spec, ← recovery_pad]
  rfl

theorem strict_accepts_implies_raw (seed root : Std.Array Std.U8 16#usize)
    (msg : Std.Array Std.U8 32#usize) (sig : C10Signature)
    (h : strictVerifierResult seed root msg sig = true) :
    rawVerifierResult seed root msg sig = true := by
  unfold strictVerifierResult Hypertree.verifyWithDigest at h
  simp only [K, show 13 - 1 = 12 from rfl] at h
  by_cases hz : (extractForsIndices (toSpecDigest (verifierDigest seed root msg sig))).getD 12 0 = 0
  · rw [if_neg (not_not.mpr hz)] at h
    cases hf : Fors.reconstructForsPk (toSpecDigest (pad16Pure seed))
        (toSpecDigest (verifierDigest seed root msg sig)) (parsedSignature sig).fors with
    | none => simp only [hf, Bool.false_eq_true] at h
    | some pk =>
      simp only [hf] at h
      cases ht : Hypertree.verifyHypertree (toSpecDigest (pad16Pure seed)) pk
          (extractHtIndex (toSpecDigest (verifierDigest seed root msg sig)))
          (parsedSignature sig).layers with
      | none => simp only [ht, Bool.false_eq_true] at h
      | some expected =>
        simp only [ht] at h
        have he := strict_hypertree_success_eq_raw (pad16Pure seed) sig pk expected
          (extractHtIndex (toSpecDigest (verifierDigest seed root msg sig))) ht
        simpa only [rawVerifierResult, if_neg (not_not.mpr hz), hf, ← he] using h
  · simp only [if_pos hz, Bool.false_eq_true] at h

/-- A successful faithful strict byte-level verification is accepted by the
    actual Rust verifier. The converse is intentionally not claimed. -/
theorem firmware_verify_accepts_strict_signature (seed root : Std.Array Std.U8 16#usize)
    (msg : Std.Array Std.U8 32#usize) (sig : C10Signature)
    (h : Signature.verify ⟨toSpecNode seed, toSpecNode root⟩ (toSpecDigest msg)
      (toSpecSignatureBytes sig) = true) :
    hypertree.verify seed root msg sig ⦃ r => r = true ⦄ := by
  rw [byteVerifier_eq_strictResult] at h
  have hraw := strict_accepts_implies_raw seed root msg sig h
  simpa only [hraw] using firmware_verify_raw_result seed root msg sig

/-- Successful strict reconstruction, including a final root mismatch,
    determines the same Boolean decision in the actual verifier. -/
theorem firmware_verify_matches_strict_success
    (seed root : Std.Array Std.U8 16#usize) (msg : Std.Array Std.U8 32#usize)
    (sig : C10Signature) (pk expected : ByteVec 16)
    (hf : Fors.reconstructForsPk (toSpecDigest (pad16Pure seed))
      (toSpecDigest (verifierDigest seed root msg sig)) (parsedSignature sig).fors = some pk)
    (ht : Hypertree.verifyHypertree (toSpecDigest (pad16Pure seed)) pk
      (extractHtIndex (toSpecDigest (verifierDigest seed root msg sig)))
      (parsedSignature sig).layers = some expected) :
    hypertree.verify seed root msg sig ⦃ r =>
      r = Signature.verify ⟨toSpecNode seed, toSpecNode root⟩ (toSpecDigest msg)
        (toSpecSignatureBytes sig) ⦄ := by
  have he := strict_hypertree_success_eq_raw (pad16Pure seed) sig pk expected
    (extractHtIndex (toSpecDigest (verifierDigest seed root msg sig))) ht
  have eqmodel : rawVerifierResult seed root msg sig =
      Signature.verify ⟨toSpecNode seed, toSpecNode root⟩ (toSpecDigest msg)
        (toSpecSignatureBytes sig) := by
    rw [byteVerifier_eq_strictResult]
    simp only [rawVerifierResult, strictVerifierResult, Hypertree.verifyWithDigest,
      K, show 13 - 1 = 12 from rfl, hf, ht, ← he]
  simpa only [eqmodel] using firmware_verify_raw_result seed root msg sig

/-- The forced-zero refusal agrees with the strict byte-level verifier on
    every signature with a nonzero final FORS field. -/
theorem firmware_verify_strict_forced_refusal (seed root : Std.Array Std.U8 16#usize)
    (msg : Std.Array Std.U8 32#usize) (sig : C10Signature)
    (hbad : (extractForsIndices (toSpecDigest (verifierDigest seed root msg sig))).getD 12 0 ≠ 0) :
    hypertree.verify seed root msg sig ⦃ r => r = false ∧
      Signature.verify ⟨toSpecNode seed, toSpecNode root⟩ (toSpecDigest msg)
        (toSpecSignatureBytes sig) = false ⦄ := by
  let* ⟨r, hr⟩ ← firmware_verify_raw_result seed root msg sig
  constructor
  · simpa only [rawVerifierResult, if_pos hbad] using hr
  · rw [byteVerifier_eq_strictResult]
    simp only [strictVerifierResult, Hypertree.verifyWithDigest, K,
      show 13 - 1 = 12 from rfl, if_pos hbad]

end Extracted.Equiv
