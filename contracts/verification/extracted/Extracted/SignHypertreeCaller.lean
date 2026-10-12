/- Connect the two-layer theorem to the real post-FORS caller. -/
import Extracted.SignHypertreeProperties
import Extracted.SignForestSerializeCaller
import Extracted.ForsPkSpec
import Extracted.HypertreeContinuationSpec
open Aeneas Aeneas.Std Result ControlFlow Error
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 200000
set_option maxRecDepth 8192
set_option pp.explicit true

def signerRootCheck (pk_root : Std.Array Std.U8 16#usize)
    (progress : hypertree.ProgressSink) (sig : C10Signature)
    (node : Std.Array Std.U8 16#usize) : Result C10Signature := do
  hypertree.report progress 100#u8
  let right_val1 ← params.SIGNATURE_LEN
  massert (4008#usize = right_val1)
  let b ←
    core.array.equality.PartialEqArray.eq core.cmp.PartialEqU8 node
      pk_root
  if b
  then ok sig
  else
    let _ ←
      core.fmt.Arguments.from_str (toStr
        "Signing self-verification failed: root mismatch" (by (conv_lhs => rw [← String.ofList_toList (s := "Signing self-verification failed: root mismatch"), String.toByteArray_ofList]); simp only [List.utf8Encode, List.size_toByteArray]; simp [String.utf8EncodeChar]; scalar_tac))
    fail panic

def pureSignerAfterForest (sk seed : Std.Array Std.U8 32#usize)
    (root : Std.Array Std.U8 16#usize) (progress : hypertree.ProgressSink)
    (sig : C10Signature) (ht : Std.U32) (roots : SignForestNodes) : Result C10Signature := do
  let (out,node) ← pureSignHypertree seed sk sig
    (th_multi_pure seed (forsPkAdrs ht) (Array.to_slice roots)) ht
  signerRootCheck root progress out node

theorem firmware_signer_hypertree_suffix (sk seed : Std.Array Std.U8 32#usize)
    (root : Std.Array Std.U8 16#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) (sig : C10Signature)
    (ht : Std.U32) (roots : SignForestNodes) :
    signerAfterSerializedForest sk seed root progress shuffle sig ht 2336#usize roots =
      pureSignerAfterForest sk seed root progress sig ht roots := by
  obtain ⟨pk,hpk,hvalue⟩ := WP.spec_imp_exists (fors_pk_spec seed ht roots)
  rw [hvalue] at hpk
  unfold signerAfterSerializedForest pureSignerAfterForest
  rw [hpk]
  have hc : UScalar.cast .U32 2#usize = 2#u32 := by
    apply UScalar.eq_of_val_eq
    rw [UScalar.cast_val_eq]
    decide
  simp only [params.D, lift, hc, bind_tc_ok]
  rw [firmware_sign_hypertree_loop]
  simp only [bind_assoc_eq]
  rw [bind_eq_iff]
  rintro ⟨out,node⟩ _
  simp only [uncurry_apply_pair, bind_tc_ok, signerRootCheck]

theorem firmware_signer_after_forest_pure (sk seed : Std.Array Std.U8 32#usize)
    (root : Std.Array Std.U8 16#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) (sig : C10Signature)
    (ht : Std.U32) (roots secrets : SignForestNodes) (paths : SignForestPaths) :
    signerAfterForest sk seed root progress shuffle sig ht 16#usize 12#usize roots secrets paths =
      pureSignerAfterForest sk seed root progress (serializedForest sig secrets paths) ht roots := by
  rw [firmware_signer_forest_serialization, firmware_signer_hypertree_suffix]

/-- Matching the computed public root passes the existing self-check. -/
theorem signer_root_check_match (root : Std.Array Std.U8 16#usize)
    (progress : hypertree.ProgressSink) (sig : C10Signature) :
    signerRootCheck root progress sig root = .ok sig := by
  obtain ⟨len,hlen,he⟩ := WP.spec_imp_exists verifier_signature_len
  rw [he] at hlen
  obtain ⟨b,hb,hbeq⟩ := WP.spec_imp_exists (verifier_node_compare root root)
  have htrue : b = true := hbeq.mpr rfl
  rw [htrue] at hb
  unfold signerRootCheck
  simp only [hypertree.report, bind_tc_ok, hlen]
  simp only [massert, if_true, bind_tc_ok, hb, Bool.true_eq]

end
end Extracted.Equiv
