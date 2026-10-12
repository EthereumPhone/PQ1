/- Actual FORS compression of all thirteen roots, with domain and position. -/
import Extracted.ForsPk.Funs
import Extracted.WotsRecoveryBridge
import Extracted.ForsForestVendored
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10
open SphincsCVerify.Spec

private theorem byteVec_ext {n : Nat} {a b : ByteVec n} (h : a.data = b.data) : a = b := by
  cases a; cases b; cases h; rfl

def forsPkAdrs (ht : Std.U32) : Std.Array Std.U8 32#usize :=
  ⟨(specMakeAdrs 0 ht.val 4 0 0 0 0).map
      (fun n => (⟨BitVec.ofNat 8 n⟩ : Std.U8)), by simp [specMakeAdrs, u32be, u64be]⟩

theorem fors_pk_spec (seed : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (roots : Std.Array (Std.Array Std.U8 16#usize) 13#usize) :
    fors.compute_fors_pk seed ht roots ⦃ r =>
      r = th_multi_pure seed (forsPkAdrs ht) ((Array.to_slice roots)) ⦄ := by
  unfold fors.compute_fors_pk
  simp only [lift, core.convert.num.FromU64U32.from]
  let* ⟨adrs, hadrs⟩ ← make_adrs_spec 0#u32
    (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64) params.ADRS_FORS_ROOTS 0#u32 0#u32 0#u32 0#u32
  have hht : (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64).val = ht.val :=
    BitVec.toNat_setWidth_of_le (by decide)
  have ha : forsPkAdrs ht = adrs := by
    apply Subtype.ext
    change (specMakeAdrs 0 ht.val 4 0 0 0 0).map
      (fun n => (⟨BitVec.ofNat 8 n⟩ : Std.U8)) = adrs.val
    have hh : adrs.val.map (·.val) = specMakeAdrs 0 ht.val 4 0 0 0 0 := by
      simpa only [params.ADRS_FORS_ROOTS, hht] using hadrs
    rw [← hh, List.map_map]
    conv_rhs => rw [← List.map_id adrs.val]
    apply List.map_congr_left
    intro x _
    exact U8.mk_ofNat_val x
  let* ⟨r, hr⟩ ← hash.th_multi_spec seed adrs (Array.to_slice roots) (by
    have h := roots.property
    simpa using (show roots.val.length ≤ 43 by omega))
  simpa only [ha] using hr

attribute [local irreducible] Adrs.make
private theorem fors_pk_adrs (ht : Std.U32) :
    toSpecDigest (forsPkAdrs ht) = Adrs.forsRoots (UInt64.ofNat ht.val) := by
  have hx := specMakeAdrs_eq_vendored 0 4 0 0 0 0 (UInt64.ofNat ht.val)
  have ht' : (UInt64.ofNat ht.val).toNat = ht.val :=
    Nat.mod_eq_of_lt (by have hb : ht.val < 2^32 := ht.hBounds; omega)
  simp only [ht'] at hx
  change _ = specMakeAdrs 0 ht.val 4 0 0 0 0 at hx
  apply byteVec_ext
  apply _root_.Array.toList_inj.mp
  change (specMakeAdrs 0 ht.val 4 0 0 0 0).map
    (fun n => UInt8.ofNat (⟨BitVec.ofNat 8 n⟩ : Std.U8).val) = _
  rw [← hx, List.map_map]
  have roundtrip (x : UInt8) : UInt8.ofNat (⟨BitVec.ofNat 8 x.toNat⟩ : Std.U8).val = x := by
    apply UInt8.toNat_inj.mp
    change (x.toNat % 256) % 256 = x.toNat
    have hx : x.toNat < 256 := x.toFin.isLt
    omega
  simp only [Function.comp_def, roundtrip, List.map_id']
  simp only [Adrs.forsRoots, ADRS_FORS_ROOTS, show UInt32.ofNat 4 = 4 from rfl]

attribute [local irreducible] thMulti
/-- All thirteen input roots agree in order, including the forced-zero tree root. -/
theorem firmware_fors_pk_matches_vendored (seed : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (roots : Std.Array (Std.Array Std.U8 16#usize) 13#usize) :
    fors.compute_fors_pk seed ht roots ⦃ r => toSpecNode r =
      Fors.computeForsPk (toSpecDigest seed) (UInt64.ofNat ht.val)
        (roots.val.map toSpecNode).toArray ⦄ := by
  let* ⟨r, hr⟩ ← fors_pk_spec seed ht roots
  rw [hr, recovery_th_multi, fors_pk_adrs]
  simp only [Fors.computeForsPk, Array.val_to_slice]
end Extracted.Equiv
