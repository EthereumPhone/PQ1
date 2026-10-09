/- Exact proof factoring of the generated signer at its FORS boundary.
   The remaining serialization/hypertree continuation keeps its Result,
   including failures and divergence. This file does not prove that suffix. -/
import Extracted.SignForestSpec
open Aeneas Aeneas.Std Result ControlFlow Error
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 3000000
set_option maxRecDepth 8192

def signerForsPhase (seed sk_seed : Std.Array Std.U8 32#usize)
    (ht_idx : Std.U32) (fors_indices : Std.Array Std.U32 13#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (i1 : Std.Usize) : Result (SignForestNodes × SignForestNodes × SignForestPaths) := do
  let a := Array.repeat 16#usize 0#u8
  let fors_roots := Array.repeat 13#usize a
  let a1 := Array.repeat 16#usize 0#u8
  let fors_secrets := Array.repeat 13#usize a1
  let a2 := Array.repeat 16#usize 0#u8
  let a3 := Array.repeat 11#usize a2
  let fors_auth_paths := Array.repeat 12#usize a3
  let s3 ←
    lift (Array.to_slice
      (Array.make 4#usize [ 102#u8, 111#u8, 114#u8, 115#u8 ]))
  let fors_shuffle_seed ← sphincs_c10.shuffle.ShuffleSeed.derive shuffle s3
  let fors_order ← sphincs_c10.shuffle.fisher_yates fors_shuffle_seed i1
  let (fors_roots1, fors_secrets1, fors_auth_paths1) ←
    hypertree.sign_inner_loop0 { start := 0#usize, «end» := i1 } sk_seed
      progress seed fors_indices ht_idx fors_roots fors_secrets
      fors_auth_paths fors_order
  let i2 ← lift (UScalar.cast .U32 i1)
  let last_root ← fors.compute_fors_root seed sk_seed ht_idx i2
  let fors_secrets2 ← hypertree.set_row fors_secrets1 i1 last_root
  let i3 ← lift (core.convert.num.FromU64U32.from ht_idx)
  let i4 ← lift (UScalar.cast .U32 i1)
  let last_leaf_adrs ←
    address.make_adrs 0#u32 i3 params.ADRS_FORS_TREE i4 0#u32 0#u32 0#u32
  let a4 ← hash.pad16 last_root
  let a5 ← hash.th seed last_leaf_adrs a4
  let fors_roots2 ← hypertree.set_row fors_roots1 i1 a5
  ok (fors_roots2, fors_secrets2, fors_auth_paths1)

def signerAfterForest (sk_seed seed : Std.Array Std.U8 32#usize)
    (pk_root : Std.Array Std.U8 16#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) (sig1 : Std.Array Std.U8 4008#usize)
    (ht_idx : Std.U32) (i i1 : Std.Usize)
    (fors_roots2 fors_secrets2 : SignForestNodes) (fors_auth_paths1 : SignForestPaths) :
    Result (Std.Array Std.U8 4008#usize) := do
  hypertree.report progress 32#u8
  let (sig2, offset) ←
    hypertree.sign_inner_loop1 sig1 i fors_secrets2 0#usize
  let (sig3, offset1) ←
    hypertree.sign_inner_loop2 i1 sig2 offset fors_auth_paths1 0#usize
  let right_val ← params.SIG_FORS_TOTAL
  massert (offset1 = right_val)
  let fors_pk ← fors.compute_fors_pk seed ht_idx fors_roots2
  let i5 ← lift (UScalar.cast .U32 params.D)
  let (sig4, offset2, current_node) ←
    hypertree.sign_inner_loop3 { start := 0#u32, «end» := i5 } sk_seed
      progress shuffle seed sig3 offset1 fors_pk ht_idx
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

def signerHead (sk_seed : Std.Array Std.U8 32#usize)
    (pk_seed pk_root : Std.Array Std.U8 16#usize) (msg_hash : Std.Array Std.U8 32#usize)
    (opt_rand : Option (Std.Array Std.U8 16#usize)) (progress : hypertree.ProgressSink) :
    Result (Std.Array Std.U8 32#usize × Std.Array Std.U8 4008#usize ×
      Std.Array Std.U32 13#usize × Std.U32 × Std.Usize × Std.Usize × Std.U32) := do
  let seed ← hash.pad16 pk_seed
  let sig := Array.repeat 4008#usize 0#u8
  hypertree.report progress 0#u8
  let (r, digest) ← fors.grind_r sk_seed pk_seed pk_root msg_hash opt_rand
  let i ← 0#usize + params.N
  let (s, index_mut_back) ←
    core.array.Array.index_mut (core.ops.index.IndexMutSlice
      (core.slice.index.SliceIndexRangeUsizeSlice Std.U8)) sig
      { start := 0#usize, «end» := i }
  let s1 ← lift (Array.to_slice r)
  let s2 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s s1
  let fors_indices ← fors.extract_fors_indices digest
  let ht_idx ← fors.extract_ht_index digest
  let i1 ← params.K - 1#usize
  let left_val ← Array.index_usize fors_indices i1
  ok (seed, index_mut_back s2, fors_indices, ht_idx, i, i1, left_val)

def signerAfterHead (sk_seed seed : Std.Array Std.U8 32#usize)
    (pk_root : Std.Array Std.U8 16#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) (sig : Std.Array Std.U8 4008#usize)
    (indices : Std.Array Std.U32 13#usize) (ht : Std.U32)
    (offset last : Std.Usize) (left : Std.U32) : Result (Std.Array Std.U8 4008#usize) := do
  if left = 0#u32 then
    hypertree.report progress 5#u8
    let (roots, secrets, paths) ← signerForsPhase seed sk_seed ht indices progress shuffle last
    signerAfterForest sk_seed seed pk_root progress shuffle sig ht offset last roots secrets paths
  else
    let _ ← core.fmt.Arguments.from_str (toStr "Last FORS index must be 0 after R-grinding" (by (conv_lhs => rw [← String.ofList_toList (s := "Last FORS index must be 0 after R-grinding"), String.toByteArray_ofList]); simp only [List.utf8Encode, List.size_toByteArray]; simp [String.utf8EncodeChar]; scalar_tac))
    fail panic

/-- Kernel-checked factorization of the actual extracted caller. -/
theorem signer_forest_factor (sk : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (msg : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize)) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) :
    hypertree.sign_inner sk seed root msg opt progress shuffle = (do
      let (s, sig, indices, ht, offset, last, left) ← signerHead sk seed root msg opt progress
      signerAfterHead sk s root progress shuffle sig indices ht offset last left) := by
  simp only [hypertree.sign_inner, signerHead, signerAfterHead, signerForsPhase, signerAfterForest,
    bind_assoc_eq, bind_eq_iff]
  intro s hs u hu rg hrg
  rcases rg with ⟨r, digest⟩
  simp only [uncurry_apply_pair, bind_assoc_eq, bind_tc_ok, bind_eq_iff]
  intro i hi pair hp
  rcases pair with ⟨slice, back⟩
  simp only [uncurry_apply_pair, bind_assoc_eq, bind_tc_ok, bind_eq_iff]
  intro s1 hs1 s2 hs2 indices hindices ht hht last hlast left hleft
  split <;> simp only [bind_assoc_eq, bind_eq_iff, bind_tc_ok]
  intro u hu label hlabel derived hderived order horder signed hsigned
  rcases signed with ⟨roots, secrets, paths⟩
  simp only [uncurry_apply_pair, bind_assoc_eq, bind_tc_ok]

end
end Extracted.Equiv
