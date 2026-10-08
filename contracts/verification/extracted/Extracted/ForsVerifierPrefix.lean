/- Exact factoring of the extracted verifier at the FORS/WOTS boundary.
   The remaining continuation is preserved as a Result, including failures
   and divergence; no accepting-verifier theorem is assumed. -/
import Extracted.ForsPrefixSpec
open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10 SphincsCVerify.Spec
set_option maxHeartbeats 4000000
set_option maxRecDepth 8192

def readVerifierRandomizer (sig : C10Signature) : Result (Std.Usize × Std.Array Std.U8 16#usize) := do
  let r := Array.repeat 16#usize 0#u8
  let (s, to_slice_mut_back) ← lift (Array.to_slice_mut r)
  let i ← 0#usize + params.N
  let s1 ←
    core.array.Array.index (core.ops.index.IndexSlice
      (core.slice.index.SliceIndexRangeUsizeSlice Std.U8)) sig
      { start := 0#usize, «end» := i }
  let s2 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s s1
  let r1 := to_slice_mut_back s2
  ok (i, r1)

def verifierHead (pk_seed pk_root : Std.Array Std.U8 16#usize)
    (msg_hash : Std.Array Std.U8 32#usize) (sig : C10Signature) :
    Result (Std.Array Std.U8 32#usize × Std.Array Std.U32 13#usize × Std.U32 × Std.Usize) := do
  let seed ← hash.pad16 pk_seed
  let root ← hash.pad16 pk_root
  let (i, r) ← readVerifierRandomizer sig
  let r_b32 ← hash.pad16 r
  let digest ← hash.h_msg seed root r_b32 msg_hash
  let indices ← fors.extract_fors_indices digest
  let ht ← fors.extract_ht_index digest
  ok (seed, indices, ht, i)

/-- Exact post-header program, factored solely for the proof below. -/
def verifierAfterHead (seed : Std.Array Std.U8 32#usize) (pk_root : Std.Array Std.U8 16#usize)
    (sig : C10Signature) (fors_indices : Std.Array Std.U32 13#usize)
    (ht_idx : Std.U32) (i : Std.Usize) : Result Bool := do
  let i1 ← params.K - 1#usize
  let i2 ← Array.index_usize fors_indices i1
  if i2 != 0#u32
  then ok false
  else
    let a := Array.repeat 16#usize 0#u8
    let fors_secrets := Array.repeat 13#usize a
    let a1 := Array.repeat 16#usize 0#u8
    let fors_roots := Array.repeat 13#usize a1
    let (offset, fors_secrets1) ←
      hypertree.verify_loop0 { start := 0#usize, «end» := params.K } sig i
        fors_secrets
    let a2 := Array.repeat 16#usize 0#u8
    let a3 := Array.repeat 11#usize a2
    let auth_paths := Array.repeat 12#usize a3
    let (offset1, auth_paths1) ←
      hypertree.verify_loop1 { start := 0#usize, «end» := i1 } sig offset
        auth_paths
    let fors_roots1 ←
      hypertree.verify_loop2 { start := 0#usize, «end» := i1 } seed
        fors_indices ht_idx fors_secrets1 fors_roots auth_paths1
    let i3 ← lift (core.convert.num.FromU64U32.from ht_idx)
    let i4 ← lift (UScalar.cast .U32 i1)
    let last_adrs ←
      address.make_adrs 0#u32 i3 params.ADRS_FORS_TREE i4 0#u32 0#u32 0#u32
    let a4 ← Array.index_usize fors_secrets1 i1
    let a5 ← hash.pad16 a4
    let a6 ← hash.th seed last_adrs a5
    let fors_roots2 ← Array.update fors_roots1 i1 a6
    let fors_pk ← fors.compute_fors_pk seed ht_idx fors_roots2
    let i5 ← lift (UScalar.cast .U32 params.D)
    let (offset2, current_node) ←
      hypertree.verify_loop3 { start := 0#u32, «end» := i5 } sig seed offset1
        fors_pk ht_idx
    let right_val ← params.SIGNATURE_LEN
    massert (offset2 = right_val)
    core.array.equality.PartialEqArray.eq core.cmp.PartialEqU8 current_node
      pk_root


/-- The actual remaining verifier, with the proved FORS end offset. -/
def verifierHypertreeContinuation (seed : Std.Array Std.U8 32#usize) (pk_root : Std.Array Std.U8 16#usize)
    (sig : C10Signature) (fors_pk : Std.Array Std.U8 16#usize) (ht_idx : Std.U32) : Result Bool := do
  let i5 ← lift (UScalar.cast .U32 params.D)
  let (offset2, current_node) ←
    hypertree.verify_loop3 { start := 0#u32, «end» := i5 } sig seed 2336#usize
      fors_pk ht_idx
  let right_val ← params.SIGNATURE_LEN
  massert (offset2 = right_val)
  core.array.equality.PartialEqArray.eq core.cmp.PartialEqU8 current_node
    pk_root


theorem verifier_head_factor (seed root : Std.Array Std.U8 16#usize)
    (msg : Std.Array Std.U8 32#usize) (sig : C10Signature) :
    hypertree.verify seed root msg sig = (do
      let (s, indices, ht, i) ← verifierHead seed root msg sig
      verifierAfterHead s root sig indices ht i) := by
  simp only [hypertree.verify, verifierHead, readVerifierRandomizer, verifierAfterHead,
    bind_assoc_eq, bind_eq_iff]
  intro s hs r hr p hp
  rcases p with ⟨a, b⟩
  simp only [uncurry_apply_pair, bind_assoc_eq, bind_tc_ok]

/-- The first sixteen signature bytes are copied without changing their order. -/
theorem readVerifierRandomizer_spec (sig : C10Signature) :
    readVerifierRandomizer sig ⦃ r => r.1 = 16#usize ∧ r.2 = verifierRandomizer sig ⦄ := by
  unfold readVerifierRandomizer
  step
  step
  step
  · have hlen := sig.property
    simp_all [params.N, Slice.length, Array.val_to_slice]
  step
  · simp only [s1_post2, i_post, params.N, Nat.zero_add, Nat.sub_zero, Slice.length,
      r_post1, Array.repeat_val, List.length_replicate]
  constructor
  · apply UScalar.eq_of_val_eq
    simpa only [params.N] using i_post
  · apply Subtype.ext
    simp only [r_post2, s2_post]
    rw [Array.from_slice_val _ _ (by simpa only [Slice.length, i_post, params.N,
      Nat.zero_add, Nat.sub_zero] using s1_post2)]
    simp only [s1_post1, i_post, params.N, Array.val_to_slice, verifierRandomizer,
      List.slice, Nat.zero_add, Nat.sub_zero, List.drop_zero]
    rfl

/-- Header execution uses the canonical R-prefixed digest and both complete decoders. -/
theorem verifierHead_spec (seed root : Std.Array Std.U8 16#usize)
    (msg : Std.Array Std.U8 32#usize) (sig : C10Signature) :
    verifierHead seed root msg sig ⦃ r =>
      r.1 = pad16Pure seed ∧ r.2.2.2 = 16#usize ∧
      r.2.2.1.val = SphincsCVerify.Util.extractHtIndex (toSpecDigest (verifierDigest seed root msg sig)) ∧
      ∀ j, j < 13 → r.2.1.val[j]!.val =
        (SphincsCVerify.Util.extractForsIndices (toSpecDigest (verifierDigest seed root msg sig))).getD j 0 ⦄ := by
  unfold verifierHead
  let* ⟨s, hs⟩ ← pad16_pure_spec seed
  let* ⟨r, hr⟩ ← pad16_pure_spec root
  let* ⟨i, randomizer, hi, hrandom⟩ ← readVerifierRandomizer_spec sig
  rw [hrandom]
  let* ⟨rb, hrb⟩ ← pad16_pure_spec (verifierRandomizer sig)
  rw [hs, hr, hrb, hash.h_msg_spec]
  simp only [bind_tc_ok]
  rw [← verifierDigest]
  let* ⟨indices, hindices⟩ ← firmware_extract_fors_indices_matches_vendored (verifierDigest seed root msg sig)
  let* ⟨ht, hht⟩ ← firmware_extract_ht_index_matches_vendored (verifierDigest seed root msg sig)
  exact ⟨hi, hht, hindices⟩

/-- The actual post-header block parses exactly the proved arrays and then
    executes the forest phase before its unchanged continuation. -/
theorem verifier_after_head_factor (seed : Std.Array Std.U8 32#usize)
    (root : Std.Array Std.U8 16#usize) (sig : C10Signature)
    (indices : Std.Array Std.U32 13#usize) (ht : Std.U32)
    (hzero : indices.val[12]!.val = 0) :
    verifierAfterHead seed root sig indices ht 16#usize = (do
      let pk ← forsForestPhase seed ht indices (parsedForsSecrets sig) (parsedForsAuth sig)
      verifierHypertreeContinuation seed root sig pk ht) := by
  obtain ⟨n, hn, hnv, _⟩ := WP.spec_imp_exists
    (Std.Usize.sub_spec (x := 13#usize) (y := 1#usize) (by scalar_tac))
  have hne : n = 12#usize := by apply UScalar.eq_of_val_eq; scalar_tac
  subst n
  obtain ⟨last, hl, hlv⟩ := WP.spec_imp_exists (Array.index_usize_spec indices 12#usize (by scalar_tac))
  have hle : last = 0#u32 := by
    apply UScalar.eq_of_val_eq
    rw [hlv]
    change indices.val[12].val = 0
    rw [← getElem!_pos indices.val 12 (by have h := indices.property; simp_all)]
    exact hzero
  rw [hle] at hl
  obtain ⟨⟨offset, secrets⟩, hs, hos, hsecrets⟩ := WP.spec_imp_exists
    (firmware_parse_fors_secrets_value sig (Array.repeat 13#usize (Array.repeat 16#usize 0#u8)))
  dsimp only at hos hsecrets
  subst offset
  subst secrets
  obtain ⟨⟨offset, paths⟩, ha, hoa, hpaths⟩ := WP.spec_imp_exists
    (firmware_parse_fors_auth_value sig
      (Array.repeat 12#usize (Array.repeat 11#usize (Array.repeat 16#usize 0#u8))))
  dsimp only at hoa hpaths
  subst offset
  subst paths
  have hcast : UScalar.cast .U32 12#usize = 12#u32 := by
    apply UScalar.eq_of_val_eq
    rw [UScalar.cast_val_eq]
    decide
  simp only [verifierAfterHead, params.K, hn, bind_tc_ok, hl, bne_self_eq_false,
    Bool.false_eq_true, if_false, hs, ha, uncurry_apply_pair, lift, hcast,
    forsForestPhase, verifierHypertreeContinuation, bind_assoc_eq]

/-- Every signature with a zero final FORS index reaches the WOTS/XMSS
    continuation with the complete verifier-specification FORS public key.
    This equality preserves the continuation's failure/divergence behavior. -/
theorem firmware_verify_fors_prefix (seed root : Std.Array Std.U8 16#usize)
    (msg : Std.Array Std.U8 32#usize) (sig : C10Signature)
    (hzero : (SphincsCVerify.Util.extractForsIndices
      (toSpecDigest (verifierDigest seed root msg sig))).getD 12 0 = 0) :
    ∃ (pk : Std.Array Std.U8 16#usize) (ht : Std.U32),
      ht.val = SphincsCVerify.Util.extractHtIndex (toSpecDigest (verifierDigest seed root msg sig)) ∧
      Fors.reconstructForsPk (toSpecDigest (pad16Pure seed))
        (toSpecDigest (verifierDigest seed root msg sig))
        (toSpecForsSig (parsedForsSecrets sig) (parsedForsAuth sig)) = some (toSpecNode pk) ∧
      hypertree.verify seed root msg sig =
        verifierHypertreeContinuation (pad16Pure seed) root sig pk ht := by
  obtain ⟨⟨s, indices, ht, i⟩, hhead, hs, hi, hht, hindices⟩ :=
    WP.spec_imp_exists (verifierHead_spec seed root msg sig)
  dsimp only at hs hi hht hindices
  subst s
  subst i
  obtain ⟨pk, hpk, hspec⟩ := WP.spec_imp_exists
    (forsForestPhase_matches_vendored (pad16Pure seed) (verifierDigest seed root msg sig)
      ht indices (parsedForsSecrets sig) (parsedForsAuth sig) hht hindices hzero)
  refine ⟨pk, ht, hht, hspec, ?_⟩
  rw [verifier_head_factor, hhead]
  simp only [bind_tc_ok, uncurry_apply_pair]
  rw [verifier_after_head_factor _ _ _ _ _ (by rw [hindices 12 (by decide)]; exact hzero), hpk]
  simp only [bind_tc_ok]

end Extracted.Equiv
