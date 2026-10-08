/- The actual verifier's twelve-root FORS loop. The thirteenth slot is preserved
   for the separate forced-zero leaf. No full-verifier equality is asserted. -/
import Extracted.Verify.Funs
import Extracted.ForsRecoveryBridge
import Extracted.ForsPkSpec
import Extracted.HashSpecs.HMsg
open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10
open SphincsCVerify.Spec
set_option maxHeartbeats 4000000
set_option maxRecDepth 8192

private abbrev ForestRoots := Std.Array (Std.Array Std.U8 16#usize) 13#usize

def forsNormalRoot (seed : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize)
    (secrets : Std.Array (Std.Array Std.U8 16#usize) 13#usize)
    (paths : Std.Array (Std.Array (Std.Array Std.U8 16#usize) 11#usize) 12#usize)
    (j : Nat) : ByteVec 16 :=
  Fors.reconstructRoot (toSpecDigest seed) (UInt64.ofNat ht.val) (UInt32.ofNat j)
    (UInt32.ofNat (indices.val[j]!).val) (toSpecNode (secrets.val[j]!))
    ((paths.val[j]!).val.map toSpecNode).toArray

attribute [local irreducible] Fors.reconstructRoot
/-- Every normal-tree root is computed from the matching input position; the
    last slot is unchanged. All seed, position, index and byte inputs are free. -/
theorem firmware_fors_normal_roots (seed : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize)
    (secrets initial : Std.Array (Std.Array Std.U8 16#usize) 13#usize)
    (paths : Std.Array (Std.Array (Std.Array Std.U8 16#usize) 11#usize) 12#usize) :
    hypertree.verify_loop2 {start := 0#usize, «end» := 12#usize}
      seed indices ht secrets initial paths ⦃ r =>
      ∀ j, j < 13 → toSpecNode (r.val[j]!) =
        if j < 12 then forsNormalRoot seed ht indices secrets paths j
        else toSpecNode (initial.val[j]!) ⦄ := by
  unfold hypertree.verify_loop2
  apply loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize ×
        ForestRoots) => 12 - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize ×
        ForestRoots) =>
      s.1.«end».val = 12 ∧ s.1.start.val ≤ 12 ∧
      ∀ j, j < 13 → toSpecNode (s.2.val[j]!) =
        if j < s.1.start.val then forsNormalRoot seed ht indices secrets paths j
        else toSpecNode (initial.val[j]!))
  · rintro ⟨it, roots⟩ ⟨hend, hle, hinv⟩
    simp only at hend hle hinv
    unfold hypertree.verify_loop2.body
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨j, it', heq, hj, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      have h : it.start.val = 12 := by omega
      simpa only [h] using hinv
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hjv : j.val = it.start.val := by rw [hj]
      have hj12 : j.val < 12 := by omega
      have hindices : indices.val.length = 13 := by simpa using indices.property
      have hsecrets : secrets.val.length = 13 := by simpa using secrets.property
      have hpaths : paths.val.length = 12 := by simpa using paths.property
      have hroots : roots.val.length = 13 := by simpa using roots.property
      simp only [lift]
      let* ⟨ix, hix⟩ ← Array.index_usize_spec indices j (by scalar_tac)
      let* ⟨secret, hs⟩ ← Array.index_usize_spec secrets j (by scalar_tac)
      let* ⟨path, hp⟩ ← Array.index_usize_spec paths j (by scalar_tac)
      let* ⟨root, hr⟩ ← firmware_fors_recovery_matches_vendored seed ht
        (UScalar.cast UScalarTy.U32 j) ix secret path
      have hcast : (UScalar.cast UScalarTy.U32 j).val = j.val := by
        rw [UScalar.cast_val_eq]; exact Nat.mod_eq_of_lt (by norm_num; omega)
      have hroot : toSpecNode root = forsNormalRoot seed ht indices secrets paths j.val := by
        rw [hr, hcast, hix, hs, hp]
        simp only [forsNormalRoot, getElem!_pos indices.val j.val (by omega),
          getElem!_pos secrets.val j.val (by omega),
          getElem!_pos paths.val j.val (by omega)]
      step* <;> first | scalar_tac | skip
      refine ⟨by rw [hend']; exact hend, by omega, ?_, by omega⟩
      intro k hk
      rw [a3_post, Array.set_val_eq]
      by_cases he : k = j.val
      · subst k
        rw [List.set_getElem!_eq _ _ _ _ ⟨by omega, rfl⟩, hroot,
          if_pos (by omega)]
      · rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega), hinv k hk]
        have hequiv : k < it.start.val ↔ k < iter1.start.val := by omega
        simp only [hequiv]
  · refine ⟨rfl, by simp, ?_⟩
    intro j _
    simp
end Extracted.Equiv
