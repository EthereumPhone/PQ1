/- Compose both actual verifier layers without assuming WOTS acceptance. -/
import Extracted.HypertreeLayerSpec
open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10 SphincsCVerify.Spec
set_option maxHeartbeats 4000000
set_option maxRecDepth 8192

def rawHypertreeRoot (seed : Std.Array Std.U8 32#usize) (sig : C10Signature)
    (idx : Nat) (current : ByteVec 16) : ByteVec 16 :=
  rawLayerRoot seed sig ⟨1, by decide⟩ (idx / 512)
    (rawLayerRoot seed sig ⟨0, by decide⟩ idx current)

/-- The loop invariant uses this only for n = 0, 1 or 2. -/
def rawLayerPrefix (seed : Std.Array Std.U8 32#usize) (sig : C10Signature)
    (idx : Nat) (current : ByteVec 16) (n : Nat) : ByteVec 16 :=
  if n = 0 then current
  else if n = 1 then rawLayerRoot seed sig ⟨0, by decide⟩ idx current
  else rawHypertreeRoot seed sig idx current

theorem rawLayerPrefix_step (seed : Std.Array Std.U8 32#usize) (sig : C10Signature)
    (idx : Nat) (current : ByteVec 16) (n : Fin 2) :
    rawLayerRoot seed sig n (idx / 512^n.val) (rawLayerPrefix seed sig idx current n.val) =
      rawLayerPrefix seed sig idx current (n.val + 1) := by
  fin_cases n <;> simp [rawLayerPrefix, rawHypertreeRoot]

/-- The actual loop consumes exactly both 836-byte layers and returns the
    specified root for all represented inputs, including invalid WOTS sums. -/
theorem firmware_verify_hypertree_loop (seed : Std.Array Std.U8 32#usize)
    (sig : C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32) :
    hypertree.verify_loop3 {start := 0#u32, «end» := 2#u32} sig seed 2336#usize current idx
      ⦃ r => r.1 = 4008#usize ∧
        toSpecNode r.2 = rawHypertreeRoot seed sig idx.val (toSpecNode current) ⦄ := by
  unfold hypertree.verify_loop3
  apply loop.spec_decr_nat
    (measure := fun s : core.ops.range.Range Std.U32 × Std.Usize × Std.Array Std.U8 16#usize × Std.U32 =>
      2 - s.1.start.val)
    (inv := fun s : core.ops.range.Range Std.U32 × Std.Usize × Std.Array Std.U8 16#usize × Std.U32 =>
      s.1.«end».val = 2 ∧ s.1.start.val ≤ 2 ∧
      s.2.1.val = 2336 + 836*s.1.start.val ∧ s.2.2.2.val = idx.val / 512^s.1.start.val ∧
      toSpecNode s.2.2.1 = rawLayerPrefix seed sig idx.val (toSpecNode current) s.1.start.val)
  · rintro ⟨it, offset, node, tree⟩ ⟨hend, hle, hoff, htree, hnode⟩
    simp only at hend hle hoff htree hnode
    simp only
    by_cases hd : it.start.val = 2
    · unfold hypertree.verify_loop3.body
      let* ⟨ob, iter1, hpost⟩ ← next_u32_spec it
      rcases hpost with ⟨ho, _⟩ | ⟨l, it', heq, hl, hlt, hend', hstart'⟩
      · subst ho
        simp only [WP.spec_ok]
        refine ⟨UScalar.eq_of_val_eq (by scalar_tac), ?_⟩
        simpa only [hd, rawLayerPrefix, Nat.reduceEqDiff, if_false] using hnode
      · omega
    · have hl : it.start.val < 2 := by omega
      obtain ⟨res, hcall, it', off', node', tree', hr, hs', he', ho', ht', hn'⟩ :=
        WP.spec_imp_exists (firmware_verify_layer_body sig seed it offset node tree
          ⟨it.start.val, hl⟩ rfl hend hoff)
      dsimp only at hs' ho'
      rw [hcall, hr]
      simp only [WP.spec_ok]
      refine ⟨⟨he', by omega, ?_, ?_, ?_⟩, by omega⟩
      · omega
      · rw [ht', htree, hs', Nat.pow_succ, Nat.div_div_eq_div_mul]
      · rw [hn', htree, hnode, rawLayerPrefix_step, hs']
  · refine ⟨rfl, by simp, rfl, ?_, ?_⟩
    · simp
    · simp [rawLayerPrefix]
private theorem all_zip_eq (xs ys : List Std.U8) (hlen : xs.length = ys.length) :
    (xs.zip ys).all (fun p => decide (p.1 = p.2)) = decide (xs = ys) := by
  induction xs generalizing ys with
  | nil => cases ys <;> simp_all
  | cons x xs ih =>
    cases ys with
    | nil => simp_all
    | cons y ys => simp [ih ys (by simpa using hlen)]

theorem verifier_node_compare (a b : Std.Array Std.U8 16#usize) :
    core.array.equality.PartialEqArray.eq core.cmp.PartialEqU8 a b
      ⦃ r => r = true ↔ a = b ⦄ := by
  unfold core.array.equality.PartialEqArray.eq
  simp only [Array.length, if_pos rfl, core.cmp.PartialEqU8, liftFun2,
    core.cmp.impls.PartialEqU8.eq, lift]
  have hall : List.allM (fun p : Std.U8 × Std.U8 => Result.ok (decide (p.1 = p.2)))
      (a.val.zip b.val) = .ok ((a.val.zip b.val).all (fun p => decide (p.1 = p.2))) := by
    exact List.allM_pure
  rw [hall, all_zip_eq _ _ (by rw [a.property, b.property])]
  simp [WP.spec_ok, Subtype.val_inj]
  exact Iff.rfl

theorem toSpecNode_inj (a b : Std.Array Std.U8 16#usize) :
    toSpecNode a = toSpecNode b ↔ a = b := by
  constructor
  · intro h
    apply Subtype.ext
    have hm := congrArg (fun v : ByteVec 16 => v.data.toList) h
    simp only [toSpecNode, List.toList_toArray] at hm
    have hf : Function.Injective (fun x : Std.U8 => UInt8.ofNat x.val) := by
      intro x y hxy
      apply UScalar.eq_of_val_eq
      have hx : x.val < 256 := x.hBounds
      have hy : y.val < 256 := y.hBounds
      have hn := congrArg UInt8.toNat hxy
      change x.val % 256 = y.val % 256 at hn
      omega
    exact (List.map_inj_right (fun x y hxy => hf hxy)).mp hm
  · rintro rfl
    rfl

theorem verifier_signature_len : params.SIGNATURE_LEN ⦃ r => r = 4008#usize ⦄ := by
  unfold params.SIGNATURE_LEN params.SIG_HT_LAYER params.SIG_FORS_TOTAL
    params.SIG_FORS_SECRETS params.SIG_FORS_AUTH params.SUBTREE_H
  simp only [params.L, params.N, params.H, params.D, params.K, params.A, params.SIG_R]
  step* <;> first | scalar_tac | skip

/-- The full remaining caller terminates, checks the exact final offset and
    returns precisely the root comparison of the two specified layers. -/
theorem firmware_verifier_hypertree_continuation (seed : Std.Array Std.U8 32#usize)
    (root current : Std.Array Std.U8 16#usize) (sig : C10Signature) (idx : Std.U32) :
    verifierHypertreeContinuation seed root sig current idx ⦃ r =>
      r = decide (rawHypertreeRoot seed sig idx.val (toSpecNode current) = toSpecNode root) ⦄ := by
  unfold verifierHypertreeContinuation
  have hc : UScalar.cast .U32 2#usize = 2#u32 := by
    apply UScalar.eq_of_val_eq
    rw [UScalar.cast_val_eq]
    decide
  simp only [params.D, lift, hc]
  let* ⟨off, node, ho, hn⟩ ← firmware_verify_hypertree_loop seed sig current idx
  let* ⟨len, hlen⟩ ← verifier_signature_len
  rw [ho, hlen]
  step
  let* ⟨b, hb⟩ ← verifier_node_compare node root
  apply Bool.eq_iff_iff.mpr
  simp only [decide_eq_true_eq]
  rw [hb, ← toSpecNode_inj, hn]

end Extracted.Equiv
