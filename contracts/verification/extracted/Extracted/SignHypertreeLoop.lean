/- Exact composition of both signer layers; bounded failures propagate. -/
import Extracted.SignHypertreeLayer

open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 200000
set_option maxRecDepth 8192
set_option pp.explicit true

private theorem loop_bind_cont {α β γ : Type} (body : α → Result (ControlFlow α β))
    (start : α) (action : Result γ) (next : γ → α)
    (h : body start = (do let r ← action; .ok (.cont (next r)))) :
    loop body start = (do let r ← action; loop body (next r)) := by
  rw [loop.eq_1, h]
  cases action <;> rfl

theorem firmware_sign_loop_step (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig : C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32)
    (layer : Fin 2) :
    hypertree.sign_inner_loop3 (signIteration layer.val) sk progress shuffle seed
      sig (signOffset layer.val) current idx =
      (do let (out,node) ← pureSignLayer seed sk layer sig current idx
          hypertree.sign_inner_loop3 (signIteration (layer.val+1)) sk progress shuffle seed
            out (signOffset (layer.val+1)) node (signNextTree idx)) := by
  unfold hypertree.sign_inner_loop3
  apply loop_bind_cont
  exact firmware_sign_layer_body sk seed progress shuffle sig current idx layer

theorem firmware_sign_loop_done (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig : C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32) :
    hypertree.sign_inner_loop3 (signIteration 2) sk progress shuffle seed
      sig (signOffset 2) current idx = .ok (sig,4008#usize,current) := by
  have hbody : hypertree.sign_inner_loop3.body sk progress shuffle seed (signIteration 2)
      sig (signOffset 2) current idx = .ok (.done (sig,signOffset 2,current)) := by
    unfold hypertree.sign_inner_loop3.body
    obtain ⟨⟨ob,it⟩,hr,hp⟩ := WP.spec_imp_exists (next_u32_spec (signIteration 2))
    dsimp only at hp
    rcases hp with ⟨ho,_⟩ | ⟨j,it',heq,hj,hlt,he,hn⟩
    · rw [hr, ho]
      simp only [bind_tc_ok, uncurry_apply_pair]
    · have hh : (signIteration 2).start.val = 2 := by rfl
      have he : (signIteration 2).«end».val = 2 := by rfl
      omega
  have hoff : signOffset 2 = 4008#usize := by
    apply UScalar.eq_of_val_eq
    rw [sign_offset_val 2 (by decide)]
    simp
  unfold hypertree.sign_inner_loop3
  rw [loop.eq_1]
  simp only
  rw [hbody]
  simp only [hoff]

def pureSignHypertree (seed sk : Std.Array Std.U8 32#usize)
    (sig : C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32) :
    Result (C10Signature × Std.Array Std.U8 16#usize) := do
  let (sig1,node1) ← pureSignLayer seed sk ⟨0,by decide⟩ sig current idx
  pureSignLayer seed sk ⟨1,by decide⟩ sig1 node1 (signNextTree idx)

/-- The actual loop writes both specified layers and ends at byte4008.
    Equality of Results retains all bounded count failures. -/
theorem firmware_sign_hypertree_loop (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig : C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32) :
    hypertree.sign_inner_loop3 {start := 0#u32, «end» := 2#u32} sk progress shuffle seed
      sig 2336#usize current idx =
      (do let (out,node) ← pureSignHypertree seed sk sig current idx
          .ok (out,4008#usize,node)) := by
  have hiter : signIteration 0 = {start := 0#u32, «end» := 2#u32} := by rfl
  have hoff : signOffset 0 = 2336#usize := by
    apply UScalar.eq_of_val_eq
    rw [sign_offset_val 0 (by decide)]
    simp
  rw [← hiter, ← hoff, firmware_sign_loop_step sk seed progress shuffle sig current idx ⟨0,by decide⟩]
  simp only [pureSignHypertree, bind_assoc_eq]
  rw [bind_eq_iff]
  rintro ⟨sig1,node1⟩ _
  simp only [uncurry_apply_pair]
  rw [firmware_sign_loop_step sk seed progress shuffle sig1 node1 (signNextTree idx) ⟨1,by decide⟩]
  rw [bind_eq_iff]
  rintro ⟨sig2,node2⟩ _
  simp only [uncurry_apply_pair]
  exact firmware_sign_loop_done sk seed progress shuffle sig2 node2 (signNextTree (signNextTree idx))

end
end Extracted.Equiv
