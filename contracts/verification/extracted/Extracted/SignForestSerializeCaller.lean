/- Exact caller connection for the proved FORS serialization. -/
import Extracted.SignForestSerialize
open Aeneas Aeneas.Std Result ControlFlow Error
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 1000000
set_option maxRecDepth 8192

def signerAfterSerializedForest (sk_seed seed : Std.Array Std.U8 32#usize)
    (pk_root : Std.Array Std.U8 16#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) (sig : C10Signature)
    (ht_idx : Std.U32) (offset : Std.Usize) (roots : SignForestNodes) :
    Result C10Signature := do
  let fors_pk ← fors.compute_fors_pk seed ht_idx roots
  let i5 ← lift (UScalar.cast .U32 params.D)
  let (sig4, offset2, current_node) ←
    hypertree.sign_inner_loop3 { start := 0#u32, «end» := i5 } sk_seed
      progress shuffle seed sig offset fors_pk ht_idx
  hypertree.report progress 100#u8
  let right_val1 ← params.SIGNATURE_LEN
  massert (offset2 = right_val1)
  let b ←
    core.array.equality.PartialEqArray.eq core.cmp.PartialEqU8 current_node
      pk_root
  if b
  then ok sig4
  else
    let _ ←
      core.fmt.Arguments.from_str (toStr
        "Signing self-verification failed: root mismatch" (by (conv_lhs => rw [← String.ofList_toList (s := "Signing self-verification failed: root mismatch"), String.toByteArray_ofList]); simp only [List.utf8Encode, List.size_toByteArray]; simp [String.utf8EncodeChar]; scalar_tac))
    fail panic

theorem signer_serialization_factor (sk seed : Std.Array Std.U8 32#usize)
    (root : Std.Array Std.U8 16#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) (sig : C10Signature)
    (ht : Std.U32) (roots secrets : SignForestNodes) (paths : SignForestPaths) :
    signerAfterForest sk seed root progress shuffle sig ht 16#usize 12#usize roots secrets paths =
      (do
        let (out, offset) ← signerSerializeForest sig secrets paths
        let expected ← params.SIG_FORS_TOTAL
        massert (offset = expected)
        signerAfterSerializedForest sk seed root progress shuffle out ht offset roots) := by
  simp only [signerAfterForest, signerSerializeForest, signerAfterSerializedForest,
    hypertree.report, bind_tc_ok, bind_assoc_eq]
  rw [bind_eq_iff]
  rintro ⟨out,off⟩ _
  rfl

theorem firmware_signer_forest_serialization (sk seed : Std.Array Std.U8 32#usize)
    (root : Std.Array Std.U8 16#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) (sig : C10Signature)
    (ht : Std.U32) (roots secrets : SignForestNodes) (paths : SignForestPaths) :
    signerAfterForest sk seed root progress shuffle sig ht 16#usize 12#usize roots secrets paths =
      signerAfterSerializedForest sk seed root progress shuffle
        (serializedForest sig secrets paths) ht 2336#usize roots := by
  rw [signer_serialization_factor]
  obtain ⟨out,hrun,hout⟩ := WP.spec_imp_exists (firmware_serialize_forest sig secrets paths)
  rw [hout] at hrun
  rw [hrun]
  have hp : params.SIG_FORS_TOTAL = .ok 2336#usize := by
    have hv : params.SIG_FORS_TOTAL ⦃ r => r = 2336#usize ⦄ := by
      unfold params.SIG_FORS_TOTAL params.SIG_FORS_SECRETS params.SIG_FORS_AUTH
      simp only [params.SIG_R, params.N, params.K, params.A]
      step* <;> scalar_tac
    obtain ⟨v,hr,hv⟩ := WP.spec_imp_exists hv
    simpa only [hv] using hr
  rw [hp]
  rfl

end
end Extracted.Equiv
