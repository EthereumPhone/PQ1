/- Exact nonce bytes and digest fields of the real signer header. -/
import Extracted.SignNoncePure
import Extracted.SignForestFactor
import Extracted.SignWriteSpec
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 200000
set_option maxRecDepth 8192
set_option pp.explicit true
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

abbrev SignerHeadResult := Std.Array Std.U8 32#usize × C10Signature ×
  Std.Array Std.U32 13#usize × Std.U32 × Std.Usize × Std.Usize × Std.U32

def serializedNonce (r : Std.Array Std.U8 16#usize) : C10Signature :=
  signatureOverwrite (Array.repeat 4008#usize 0#u8) 0 16 (fun i => r.val[i]!)

def headerForsIndices (digest : Std.Array Std.U8 32#usize) : Std.Array Std.U32 13#usize :=
  ⟨(List.range 13).map (fun j => ⟨BitVec.ofNat 32 ((digestWord digest >>> (j*11)) % 2048)⟩),
    by simp⟩

def headerHtIndex (digest : Std.Array Std.U8 32#usize) : Std.U32 :=
  ⟨BitVec.ofNat 32 ((digestWord digest >>> 143) % 262144)⟩

theorem header_fors_index_val (digest : Std.Array Std.U8 32#usize) (j : Nat) (hj : j < 13) :
    ((headerForsIndices digest).val[j]!).val = (digestWord digest >>> (j*11)) % 2048 := by
  have hb : (digestWord digest >>> (j*11)) % 2048 < 2048 := Nat.mod_lt _ (by decide)
  simp [headerForsIndices, hj]
  exact Nat.mod_eq_of_lt (by omega : (digestWord digest >>> (j*11)) % 2048 < 2^32)

theorem header_ht_index_val (digest : Std.Array Std.U8 32#usize) :
    (headerHtIndex digest).val = (digestWord digest >>> 143) % 262144 := by
  have hb : (digestWord digest >>> 143) % 262144 < 262144 := Nat.mod_lt _ (by decide)
  change ((digestWord digest >>> 143) % 262144) % 2^32 = _
  exact Nat.mod_eq_of_lt (by omega)

theorem header_fors_indices_pure (digest : Std.Array Std.U8 32#usize) :
    fors.extract_fors_indices digest = .ok (headerForsIndices digest) := by
  obtain ⟨indices,hr,hv⟩ := WP.spec_imp_exists (extract_fors_indices_spec digest)
  have he : indices = headerForsIndices digest := by
    apply Subtype.ext
    apply List.ext_getElem! (by simp)
    intro j
    by_cases hj : j < 13
    · apply UScalar.eq_of_val_eq
      rw [hv j hj, header_fors_index_val digest j hj]
      rfl
    · simp [getElem!_neg, hj]
  simpa only [he] using hr

theorem header_ht_index_pure (digest : Std.Array Std.U8 32#usize) :
    fors.extract_ht_index digest = .ok (headerHtIndex digest) := by
  obtain ⟨ht,hr,hv⟩ := WP.spec_imp_exists (extract_ht_index_spec digest)
  have he : ht = headerHtIndex digest := by
    apply UScalar.eq_of_val_eq
    rw [hv, header_ht_index_val]
    rfl
  simpa only [he] using hr

def signerHeaderTail (seed : Std.Array Std.U8 32#usize)
    (r : Std.Array Std.U8 16#usize) (digest : Std.Array Std.U8 32#usize) : Result SignerHeadResult := do
  let sig := Array.repeat 4008#usize 0#u8
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

def pureHeaderTail (seed : Std.Array Std.U8 32#usize)
    (r : Std.Array Std.U8 16#usize) (digest : Std.Array Std.U8 32#usize) : SignerHeadResult :=
  (seed, serializedNonce r, headerForsIndices digest, headerHtIndex digest,
    16#usize, 12#usize, (headerForsIndices digest).val[12]!)

theorem signer_header_factor (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) :
    signerHead sk seed root msg opt progress = (do
      let (r,digest) ← fors.grind_r sk seed root msg opt
      signerHeaderTail (pad16Pure seed) r digest) := by
  obtain ⟨p,hp,hpv⟩ := WP.spec_imp_exists (pad16_pure_spec seed)
  rw [hpv] at hp
  simp only [signerHead, signerHeaderTail, hp, hypertree.report, bind_tc_ok]

def signerHeaderParse (seed : Std.Array Std.U8 32#usize) (sig : C10Signature)
    (digest : Std.Array Std.U8 32#usize) : Result SignerHeadResult := do
  let indices ← fors.extract_fors_indices digest
  let ht ← fors.extract_ht_index digest
  let last ← params.K - 1#usize
  let left ← Array.index_usize indices last
  ok (seed,sig,indices,ht,16#usize,last,left)

theorem header_offset_add : (0#usize + params.N : Result Std.Usize) = .ok 16#usize := by
  obtain ⟨i,hi,hv⟩ := WP.spec_imp_exists
    (Std.Usize.add_spec (x := 0#usize) (y := 16#usize) (by scalar_tac))
  have he : i = 16#usize := by apply UScalar.eq_of_val_eq; scalar_tac
  simpa only [params.N, he] using hi

theorem header_last_sub : (params.K - 1#usize : Result Std.Usize) = .ok 12#usize := by
  obtain ⟨i,hi,hv,_⟩ := WP.spec_imp_exists
    (Std.Usize.sub_spec (x := 13#usize) (y := 1#usize) (by scalar_tac))
  have he : i = 12#usize := by apply UScalar.eq_of_val_eq; scalar_tac
  simpa only [params.K, he] using hi

theorem signer_header_tail_factor (seed : Std.Array Std.U8 32#usize)
    (r : Std.Array Std.U8 16#usize) (digest : Std.Array Std.U8 32#usize) :
    signerHeaderTail seed r digest = (do
      let sig ← hypertree.write16 (Array.repeat 4008#usize 0#u8) 0#usize r
      signerHeaderParse seed sig digest) := by
  simp only [signerHeaderTail, signerHeaderParse, hypertree.write16, header_offset_add,
    bind_tc_ok, bind_assoc_eq]
  rw [bind_eq_iff]
  rintro ⟨slice,back⟩ _
  simp only [uncurry_apply_pair, bind_assoc_eq, bind_tc_ok]

theorem signer_header_parse_pure (seed : Std.Array Std.U8 32#usize) (sig : C10Signature)
    (digest : Std.Array Std.U8 32#usize) :
    signerHeaderParse seed sig digest = .ok (seed,sig,headerForsIndices digest,
      headerHtIndex digest,16#usize,12#usize,(headerForsIndices digest).val[12]!) := by
  obtain ⟨left,hl,hv⟩ := WP.spec_imp_exists
    (Array.index_usize_spec (headerForsIndices digest) 12#usize (by scalar_tac))
  have he : left = (headerForsIndices digest).val[12]! := by
    rw [hv, getElem!_pos _ _ (by simp)]
    simp
  rw [he] at hl
  simp only [signerHeaderParse, header_fors_indices_pure, header_ht_index_pure,
    header_last_sub, bind_tc_ok, hl]

/-- Every arbitrary R/digest is written and decoded with exact byte framing. -/
theorem firmware_sign_header_tail (seed : Std.Array Std.U8 32#usize)
    (r : Std.Array Std.U8 16#usize) (digest : Std.Array Std.U8 32#usize) :
    signerHeaderTail seed r digest = .ok (pureHeaderTail seed r digest) := by
  rw [signer_header_tail_factor]
  obtain ⟨out,hr,hw⟩ := WP.spec_imp_exists
    (firmware_write16 (Array.repeat 4008#usize 0#u8) 0#usize r (by decide))
  have he : out = serializedNonce r := signatureWrites_eq _ _ 0 16 _ hw
  rw [he] at hr
  rw [hr]
  simp only [bind_tc_ok, signer_header_parse_pure, pureHeaderTail]

/-- No successful nonce or signer result is assumed. -/
theorem firmware_sign_header_pure (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) :
    signerHead sk seed root msg opt progress = (do
      let (r,digest) ← pureGrindR sk msg seed root opt
      ok (pureHeaderTail (pad16Pure seed) r digest)) := by
  rw [signer_header_factor, firmware_grind_r_pure]
  rw [bind_eq_iff]
  rintro ⟨r,digest⟩ _
  exact firmware_sign_header_tail _ r digest

theorem header_indices_bound (digest : Std.Array Std.U8 32#usize) :
    (∀ j, j < 13 → ((headerForsIndices digest).val[j]!).val < 2048) ∧
      (headerHtIndex digest).val < 262144 := by
  constructor
  · intro j hj
    rw [header_fors_index_val digest j hj]
    exact Nat.mod_lt _ (by decide)
  · rw [header_ht_index_val]
    exact Nat.mod_lt _ (by decide)

theorem grind_header_forced_zero (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (r : Std.Array Std.U8 16#usize) (digest : Std.Array Std.U8 32#usize)
    (h : pureGrindR sk msg seed root opt = .ok (r,digest)) :
    (headerForsIndices digest).val[12]! = 0#u32 := by
  obtain ⟨c,hc,_,hd⟩ := pure_grind_r_success sk msg seed root opt r digest h
  apply UScalar.eq_of_val_eq
  rw [header_fors_index_val digest 12 (by decide), hd]
  exact hc.2.1

theorem serialized_nonce_bytes (r : Std.Array Std.U8 16#usize) (j : Fin 4008) :
    (serializedNonce r).val[j.val]! = if j.val < 16 then r.val[j.val]! else 0#u8 := by
  have h := signatureOverwrite_spec (Array.repeat 4008#usize 0#u8) 0 16 (fun i => r.val[i]!) j
  have hz : (Array.repeat 4008#usize 0#u8).val[j.val]! = 0#u8 := by
    change (List.replicate 4008 (0#u8))[j.val]! = 0#u8
    exact List.getElem!_replicate _ j.isLt
  simpa only [Nat.zero_le, Nat.zero_add, true_and, Nat.sub_zero, hz] using h

theorem serialized_nonce_decodes (r : Std.Array Std.U8 16#usize) :
    signatureNode (serializedNonce r) ⟨0,by decide⟩ = r := by
  apply signatureNode_eq
  intro i
  simpa using serialized_nonce_bytes r ⟨i.val,by have := i.isLt; omega⟩

end
end Extracted.Equiv
