/- Successful signer iterations emit canonical fields and preserve the prefix. -/
import Extracted.SignHypertreeLoop

open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 200000
set_option maxRecDepth 8192
set_option pp.explicit true
attribute [local irreducible] wotsSignChains xmssRootNode xmssSigningPath serializedLayer
  SphincsCVerify.Spec.Sha256Impl.sha256Bytes

theorem pure_sign_layer_success (seed sk : Std.Array Std.U8 32#usize)
    (layer : Fin 2) (sig out : C10Signature) (current node : Std.Array Std.U8 16#usize)
    (idx : Std.U32) (h : pureSignLayer seed sk layer sig current idx = .ok (out,node)) :
    ∃ count, FirstWotsCount seed (signLayerId layer) (UScalar.cast .U64 (signNextTree idx))
        (signLeaf idx) current count ∧
      out = serializedLayer sig (2336+836*layer.val)
        (wotsSignChains seed sk (wots_digest_pure seed
          (adrsArr (signLayerId layer) (UScalar.cast .U64 (signNextTree idx))
            0 (signLeaf idx).val 0 0 0) (pad16p current) count)
          (signLayerId layer) (UScalar.cast .U64 (signNextTree idx)) (signLeaf idx)) count
        (xmssSigningPath seed sk (signLayerId layer)
          (UScalar.cast .U64 (signNextTree idx)) (signLeaf idx)) ∧
      node = xmssRootNode seed sk (signLayerId layer) (UScalar.cast .U64 (signNextTree idx)) 9 0 := by
  classical
  unfold pureSignLayer pureWotsSign at h
  dsimp only at h
  split at h
  · rename_i hex
    simp only [bind_tc_ok, uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
    exact ⟨Classical.choose hex, Classical.choose_spec hex, h.1.symm, h.2.symm⟩
  · simp only [bind_tc_fail] at h
    cases h

theorem pure_sign_layer_preserves_prefix (seed sk : Std.Array Std.U8 32#usize)
    (layer : Fin 2) (sig out : C10Signature) (current node : Std.Array Std.U8 16#usize)
    (idx : Std.U32) (h : pureSignLayer seed sk layer sig current idx = .ok (out,node))
    (j : Fin 4008) (hj : j.val < 2336+836*layer.val) :
    out.val[j.val]! = sig.val[j.val]! := by
  obtain ⟨count,_,hout,_⟩ := pure_sign_layer_success seed sk layer sig out current node idx h
  rw [hout]
  exact serializedLayer_preserves sig _ _ count _ j (Or.inl hj)

/-- Every successful actual loop preserves the nonce and FORS prefix and ends
    at the root of the top tree selected by the full input index. -/
theorem firmware_sign_hypertree_success (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig out : C10Signature) (current node : Std.Array Std.U8 16#usize)
    (idx : Std.U32) (offset : Std.Usize)
    (h : hypertree.sign_inner_loop3 {start := 0#u32, «end» := 2#u32}
      sk progress shuffle seed sig 2336#usize current idx = .ok (out,offset,node)) :
    offset = 4008#usize ∧
    node = xmssRootNode seed sk 1#u32
      (UScalar.cast .U64 (signNextTree (signNextTree idx))) 9 0 ∧
    ∀ j : Fin 4008, j.val < 2336 → out.val[j.val]! = sig.val[j.val]! := by
  rw [firmware_sign_hypertree_loop] at h
  simp only [pureSignHypertree, bind_assoc_eq] at h
  cases h0 : pureSignLayer seed sk ⟨0,by decide⟩ sig current idx with
  | fail e => simp only [h0, bind_tc_fail] at h; cases h
  | div => simp only [h0, bind_tc_div] at h; cases h
  | ok pair =>
    rcases pair with ⟨sig1,node1⟩
    simp only [h0, bind_tc_ok, uncurry_apply_pair] at h
    cases h1 : pureSignLayer seed sk ⟨1,by decide⟩ sig1 node1 (signNextTree idx) with
    | fail e => simp only [h1, bind_tc_fail] at h; cases h
    | div => simp only [h1, bind_tc_div] at h; cases h
    | ok pair =>
      rcases pair with ⟨sig2,node2⟩
      simp only [h1, bind_tc_ok, uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
      rcases h with ⟨rfl,hoff,rfl⟩
      obtain ⟨_,_,_,hn⟩ := pure_sign_layer_success seed sk ⟨1,by decide⟩ sig1 sig2 node1 node2
        (signNextTree idx) h1
      refine ⟨hoff.symm, hn, ?_⟩
      intro j hj
      rw [pure_sign_layer_preserves_prefix seed sk ⟨1,by decide⟩ sig1 sig2 node1 node2
        (signNextTree idx) h1 j (by simp; omega)]
      exact pure_sign_layer_preserves_prefix seed sk ⟨0,by decide⟩ sig sig1 current node1 idx h0 j hj

theorem sign_top_tree_zero (idx : Std.U32) (hi : idx.val < 262144) :
    UScalar.cast .U64 (signNextTree (signNextTree idx)) = 0#u64 := by
  apply UScalar.eq_of_val_eq
  rw [UScalar.cast_val_eq, sign_next_tree_val, sign_next_tree_val, Nat.div_div_eq_div_mul]
  have hz : idx.val / (512*512) = 0 := Nat.div_eq_of_lt hi
  simp only [hz]
  simp

/-- For the signer's 18-bit index range the top tree is tree 0. No successful
    grinder is assumed by the unconditional loop equality above. -/
theorem firmware_sign_hypertree_top_root (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig out : C10Signature) (current node : Std.Array Std.U8 16#usize)
    (idx : Std.U32) (offset : Std.Usize) (hi : idx.val < 262144)
    (h : hypertree.sign_inner_loop3 {start := 0#u32, «end» := 2#u32}
      sk progress shuffle seed sig 2336#usize current idx = .ok (out,offset,node)) :
    node = xmssRootNode seed sk 1#u32 0#u64 9 0 := by
  have hn := (firmware_sign_hypertree_success sk seed progress shuffle sig out current node idx offset h).2.1
  simpa only [sign_top_tree_zero idx hi] using hn

end
end Extracted.Equiv
