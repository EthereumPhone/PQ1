/- The actual shuffled twelve-tree signing loop. The final slot is preserved
   here and completed separately by the caller's special-tree block. -/
import Extracted.SignForest.Funs
import Extracted.ShuffleOrder
import Extracted.ForsRoundtripSpec

open Aeneas Aeneas.Std Result ControlFlow
set_option maxHeartbeats 3000000
set_option maxRecDepth 8192
namespace Extracted.Equiv
open sphincs_c10

abbrev SignForestNodes := Std.Array (Std.Array Std.U8 16#usize) 13#usize
abbrev SignForestPath := Std.Array (Std.Array Std.U8 16#usize) 11#usize
abbrev SignForestPaths := Std.Array SignForestPath 12#usize

def forsSigningPath (seed sk : Std.Array Std.U8 32#usize) (ht tree leaf : Std.U32) :
    SignForestPath :=
  ⟨(List.range 11).map (fun h => forsRootNode seed sk ht tree h (forsAuthSibling leaf.val h)),
    by simp⟩

def forsSigningRow (seed sk : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize) (roots secrets : SignForestNodes)
    (paths : SignForestPaths) (j : Nat) : Prop :=
  roots.val[j]! = forsRootNode seed sk ht ⟨BitVec.ofNat 32 j⟩ 11 0 ∧
  secrets.val[j]! = forsSecretPure sk ht ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!) ∧
  paths.val[j]! = forsSigningPath seed sk ht ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!)

attribute [local irreducible] forsRootNode forsSigningPath forsSigningRow forsSecretPure
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

private theorem signing_path_eq (seed sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) (path : SignForestPath)
    (hp : ∀ h, h < 11 → path.val[h]! = forsRootNode seed sk ht tree h (forsAuthSibling leaf.val h)) :
    path = forsSigningPath seed sk ht tree leaf := by
  apply Subtype.ext
  unfold forsSigningPath
  apply List.ext_getElem
  · simpa using path.property
  intro h hh hh'
  rw [← getElem!_pos path.val h hh, hp h (by simpa using hh')]
  simp

private theorem forest_index_bound {n : Std.Usize} (a : Std.Array α n)
    (i : Std.Usize) (h : i.val < n.val) : i.val < a.length := by scalar_tac

private def forestProgressThen {α : Type} (j : Std.Usize)
    (progress : hypertree.ProgressSink) (next : Result α) : Result α := do
  let i5 ← UScalar.cast .U32 j + 1#u32
  let i6 ← i5 * 25#u32
  let i8 ← UScalar.cast .U32 params.K - 1#u32
  let i9 ← i6 / i8
  let i10 ← 5#u32 + i9
  hypertree.report progress (UScalar.cast .U8 i10)
  next

private theorem forest_progress_then_spec (j : Std.Usize) (progress : hypertree.ProgressSink)
    (hj : j.val < 12) {α : Type} (next : Result α) (post : α → Prop)
    (hnext : next ⦃ post ⦄) : forestProgressThen j progress next ⦃ post ⦄ := by
  have hc : (UScalar.cast .U32 j).val = j.val := by
    rw [UScalar.cast_val_eq]; exact Nat.mod_eq_of_lt (by norm_num; omega)
  have hk : UScalar.cast .U32 params.K = 13#u32 := by
    apply UScalar.eq_of_val_eq
    simp [UScalar.cast_val_eq, params.K]
  unfold forestProgressThen
  rw [hk]
  simp only [hypertree.report]
  step* <;> first | assumption | scalar_tac

/-- Every normal slot is filled from its matching tree and digest index, for
    any permutation; the caller's final slots are untouched. -/
theorem firmware_sign_fors_normal_loop (seed sk : Std.Array Std.U8 32#usize)
    (ht : Std.U32) (indices : Std.Array Std.U32 13#usize)
    (progress : hypertree.ProgressSink) (order : Std.Array Std.U8 64#usize)
    (initialRoots initialSecrets : SignForestNodes) (initialPaths : SignForestPaths)
    (hi : ∀ j, j < 12 → (indices.val[j]!).val < 2048)
    (hp : shufflePermutation 12 order) :
    hypertree.sign_inner_loop0 {start := 0#usize, «end» := 12#usize}
      sk progress seed indices ht initialRoots initialSecrets initialPaths order ⦃ r =>
      r.1.val[12]! = initialRoots.val[12]! ∧
      r.2.1.val[12]! = initialSecrets.val[12]! ∧
      ∀ j, j < 12 → forsSigningRow seed sk ht indices r.1 r.2.1 r.2.2 j ⦄ := by
  unfold hypertree.sign_inner_loop0
  apply loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize × SignForestNodes ×
        SignForestNodes × SignForestPaths) => 12 - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize × SignForestNodes ×
        SignForestNodes × SignForestPaths) =>
      s.1.«end».val = 12 ∧ s.1.start.val ≤ 12 ∧
      s.2.1.val[12]! = initialRoots.val[12]! ∧
      s.2.2.1.val[12]! = initialSecrets.val[12]! ∧
      ∀ t, t < s.1.start.val →
        forsSigningRow seed sk ht indices s.2.1 s.2.2.1 s.2.2.2 (order.val[t]!).val)
  · rintro ⟨it, roots, secrets, paths⟩ ⟨hend, hle, hlastR, hlastS, hinv⟩
    simp only at hend hle hlastR hlastS hinv
    unfold hypertree.sign_inner_loop0.body
    simp only [lift]
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨j, it', heq, hj, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      refine ⟨hlastR, hlastS, ?_⟩
      intro k hk
      obtain ⟨t, ht, htk⟩ := shuffle_order_covers 12 order (by decide) hp k hk
      simpa only [htk] using hinv t (by omega)
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hj12 : j.val < 12 := by rw [hj]; omega
      let* ⟨byte, hbyte⟩ ← Array.index_usize_spec order j (by scalar_tac)
      have hby : byte = order.val[j.val]! := by
        rw [hbyte, getElem!_pos order.val j.val (by have := order.property; scalar_tac)]
      have hb12 : byte.val < 12 := by
        rw [hby]; exact shuffle_order_bound 12 order (by decide) hp j.val hj12
      have hc : (UScalar.cast .Usize byte).val = byte.val := by
        rw [UScalar.cast_val_eq]; exact Nat.mod_eq_of_lt (by scalar_tac)
      have hc32 : (UScalar.cast .U32 (UScalar.cast .Usize byte)).val = byte.val := by
        rw [UScalar.cast_val_eq, hc]; exact Nat.mod_eq_of_lt (by scalar_tac)
      have hcast : UScalar.cast .U32 (UScalar.cast .Usize byte) =
          (⟨BitVec.ofNat 32 byte.val⟩ : Std.U32) := u32_eq_ofNat (by omega) hc32
      let* ⟨leaf, hleaf⟩ ← Array.index_usize_spec indices (UScalar.cast .Usize byte)
        (forest_index_bound _ _ (by change _ < 13; omega))
      have hl : leaf = indices.val[byte.val]! := by
        rw [hleaf, ← getElem!_pos indices.val (UScalar.cast .Usize byte).val
          (by rw [indices.property]; change _ < 13; omega), hc]
      have hlb : leaf.val < 2048 := by rw [hl]; exact hi byte.val hb12
      let* ⟨secret, path, hs, hpath⟩ ← fors_sign_tree_spec seed sk ht
        (UScalar.cast .U32 (UScalar.cast .Usize byte)) leaf hlb
      let* ⟨secrets1, hs1⟩ ← Array.update_spec secrets (UScalar.cast .Usize byte) secret
        (forest_index_bound _ _ (by change _ < 13; omega))
      let* ⟨paths1, hp1⟩ ← Array.update_spec paths (UScalar.cast .Usize byte) path
        (forest_index_bound _ _ (by change _ < 12; omega))
      let* ⟨root, hr⟩ ← fors_recovery_spec seed ht
        (UScalar.cast .U32 (UScalar.cast .Usize byte)) leaf secret path
      have hrval : root = forsRootNode seed sk ht ⟨BitVec.ofNat 32 byte.val⟩ 11 0 := by
        rw [hr, fors_auth_recovery_root seed sk ht _ leaf hlb secret path hs hpath, hcast]
      have hsval : secret = forsSecretPure sk ht ⟨BitVec.ofNat 32 byte.val⟩ (indices.val[byte.val]!) := by
        rw [hs, hcast, hl]
      have hpval : path = forsSigningPath seed sk ht ⟨BitVec.ofNat 32 byte.val⟩ (indices.val[byte.val]!) := by
        rw [signing_path_eq seed sk ht _ leaf path hpath, hcast, hl]
      let* ⟨roots1, hr1⟩ ← Array.update_spec roots (UScalar.cast .Usize byte) root
        (forest_index_bound _ _ (by change _ < 13; omega))
      apply forest_progress_then_spec j progress hj12
      simp only [WP.spec_ok]
      refine ⟨by rw [hend']; exact hend, by omega, ?_, ?_, ?_, by omega⟩
      · rw [hr1, Array.set_val_eq, hc, List.set_getElem!_ne _ _ _ _ (by omega)]
        exact hlastR
      · rw [hs1, Array.set_val_eq, hc, List.set_getElem!_ne _ _ _ _ (by omega)]
        exact hlastS
      · intro t ht
        unfold forsSigningRow
        rw [hr1, hs1, hp1, Array.set_val_eq, Array.set_val_eq, Array.set_val_eq, hc]
        have ht12 : t < 12 := by omega
        have htv := shuffle_order_bound 12 order (by decide) hp t ht12
        by_cases he : (order.val[t]!).val = byte.val
        · rw [he, List.set_getElem!_eq _ _ _ _ ⟨by rw [roots.property]; change _ < 13; omega, rfl⟩,
            List.set_getElem!_eq _ _ _ _ ⟨by rw [secrets.property]; change _ < 13; omega, rfl⟩,
            List.set_getElem!_eq _ _ _ _ ⟨by rw [paths.property]; exact hb12, rfl⟩]
          exact ⟨hrval, hsval, hpval⟩
        · rw [List.set_getElem!_ne _ _ _ _ (by omega),
            List.set_getElem!_ne _ _ _ _ (by omega), List.set_getElem!_ne _ _ _ _ (by omega)]
          have hprev : t < it.start.val := by
            have hne : t ≠ j.val := by intro h; apply he; rw [h, ← hby]
            rw [hstart'] at ht
            rw [hj] at hne
            omega
          simpa only [forsSigningRow] using hinv t hprev
  · exact ⟨rfl, by simp, rfl, rfl, by simp⟩

end Extracted.Equiv
