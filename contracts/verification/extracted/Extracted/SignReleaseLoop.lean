/- Release-configured caller loops, with the same explicit opaque helper models. -/
import Extracted.SignRelease.Funs
import Extracted.SignHypertreeProperties
open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 200000
set_option maxRecDepth 8192

abbrev SignLoopState := core.ops.range.Range Std.U32 × C10Signature × Std.Usize ×
  Std.Array Std.U8 16#usize × Std.U32

def releaseLoopExit (cf : ControlFlow SignLoopState
    (C10Signature × Std.Usize × Std.Array Std.U8 16#usize)) :
    ControlFlow SignLoopState C10Signature :=
  match cf with
  | .cont state => .cont state
  | .done (sig,_,_) => .done sig

theorem release_layer_body_projection (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (iter : core.ops.range.Range Std.U32) (sig : C10Signature) (offset : Std.Usize)
    (current : Std.Array Std.U8 16#usize) (idx : Std.U32) :
    hypertree.release_sign_inner_loop3.body sk progress shuffle seed iter sig offset current idx =
      (do let cf ← hypertree.sign_inner_loop3.body sk progress shuffle seed iter sig offset current idx
          .ok (releaseLoopExit cf)) := by
  simp only [hypertree.release_sign_inner_loop3.body, hypertree.sign_inner_loop3.body,
    bind_assoc_eq, bind_eq_iff, Prod.forall, uncurry_apply_pair, bind_tc_ok]
  intro o it h
  cases o with
  | none => rfl
  | some layer =>
    simp only [bind_assoc_eq, bind_eq_iff, Prod.forall,
      uncurry_apply_pair, bind_tc_ok, releaseLoopExit]
    intros
    split <;> simp only [bind_tc_ok, bind_assoc_eq, bind_eq_iff, Prod.forall,
      uncurry_apply_pair, forall_const, implies_true]

private theorem loop_bind_cont {α β γ : Type} (body : α → Result (ControlFlow α β))
    (start : α) (action : Result γ) (next : γ → α)
    (h : body start = (do let r ← action; .ok (.cont (next r)))) :
    loop body start = (do let r ← action; loop body (next r)) := by
  rw [loop.eq_1, h]
  cases action <;> rfl

theorem firmware_release_sign_loop_step (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig : C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32)
    (layer : Fin 2) :
    hypertree.release_sign_inner_loop3 (signIteration layer.val) sk progress shuffle seed
      sig (signOffset layer.val) current idx =
      (do let (out,node) ← pureSignLayer seed sk layer sig current idx
          hypertree.release_sign_inner_loop3 (signIteration (layer.val+1)) sk progress shuffle seed
            out (signOffset (layer.val+1)) node (signNextTree idx)) := by
  unfold hypertree.release_sign_inner_loop3
  apply loop_bind_cont
  dsimp only
  rw [release_layer_body_projection, firmware_sign_layer_body]
  simp only [bind_assoc_eq]
  rw [bind_eq_iff]
  rintro ⟨out,node⟩ _
  rfl

theorem firmware_release_sign_loop_done (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig : C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32) :
    hypertree.release_sign_inner_loop3 (signIteration 2) sk progress shuffle seed
      sig (signOffset 2) current idx = .ok sig := by
  have hbody : hypertree.release_sign_inner_loop3.body sk progress shuffle seed (signIteration 2)
      sig (signOffset 2) current idx = .ok (.done sig) := by
    unfold hypertree.release_sign_inner_loop3.body
    obtain ⟨⟨ob,it⟩,hr,hp⟩ := WP.spec_imp_exists (next_u32_spec (signIteration 2))
    dsimp only at hp
    rcases hp with ⟨ho,_⟩ | ⟨j,it',heq,hj,hlt,he,hn⟩
    · rw [hr, ho]
      simp only [bind_tc_ok, uncurry_apply_pair]
    · have hh : (signIteration 2).start.val = 2 := by rfl
      have he : (signIteration 2).«end».val = 2 := by rfl
      omega
  unfold hypertree.release_sign_inner_loop3
  rw [loop.eq_1]
  simp only
  rw [hbody]

/-- The actual loop writes both specified layers and ends at byte4008.
    Equality of Results retains all bounded count failures. -/
theorem firmware_release_sign_hypertree_loop (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig : C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32) :
    hypertree.release_sign_inner_loop3 {start := 0#u32, «end» := 2#u32} sk progress shuffle seed
      sig 2336#usize current idx =
      (do let (out,node) ← pureSignHypertree seed sk sig current idx
          .ok out) := by
  have hiter : signIteration 0 = {start := 0#u32, «end» := 2#u32} := by rfl
  have hoff : signOffset 0 = 2336#usize := by
    apply UScalar.eq_of_val_eq
    rw [sign_offset_val 0 (by decide)]
    simp
  rw [← hiter, ← hoff, firmware_release_sign_loop_step sk seed progress shuffle sig current idx ⟨0,by decide⟩]
  simp only [pureSignHypertree, bind_assoc_eq]
  rw [bind_eq_iff]
  rintro ⟨sig1,node1⟩ _
  simp only [uncurry_apply_pair]
  rw [firmware_release_sign_loop_step sk seed progress shuffle sig1 node1 (signNextTree idx) ⟨1,by decide⟩]
  rw [bind_eq_iff]
  rintro ⟨sig2,node2⟩ _
  simp only [uncurry_apply_pair]
  exact firmware_release_sign_loop_done sk seed progress shuffle sig2 node2 (signNextTree (signNextTree idx))

end
end Extracted.Equiv
