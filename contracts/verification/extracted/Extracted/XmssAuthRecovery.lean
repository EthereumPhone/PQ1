/- Canonical XMSS siblings recover the root through the actual Merkle helper. -/
import Extracted.XmssAuthBridge

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 1500000
set_option maxRecDepth 8192
namespace Extracted.Equiv
attribute [local irreducible] xmssRootNode xmssAuthSibling

theorem xmss_auth_recovery_fold (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Nat) (hleaf : leaf < 512)
    (path : Std.Array (Std.Array Std.U8 16#usize) 9#usize)
    (hp : ∀ k, k < 9 → path.val[k]! = xmssRootNode seed sk layer tree k (xmssAuthSibling leaf k))
    (n h : Nat) (hb : h + n ≤ 9) :
    authFold seed layer tree ((path.val.drop h).take n)
      (xmssRootNode seed sk layer tree h (leaf / 2^h)) (leaf / 2^h) h =
      xmssRootNode seed sk layer tree (h+n) (leaf / 2^(h+n)) := by
  have hlen : path.val.length = 9 := by simpa using path.property
  induction n generalizing h with
  | zero => simp [authFold]
  | succ n ih =>
    have hh : h < 9 := by omega
    have hhpath : h < path.val.length := by omega
    have hd : (path.val.drop h).take (n+1) =
        path.val[h] :: (path.val.drop (h+1)).take n := by
      rw [← List.cons_getElem_drop_succ (l := path.val) (n := h) (h := hhpath)]
      rfl
    have hvalue : path.val[h] = xmssRootNode seed sk layer tree h (xmssAuthSibling leaf h) := by
      rw [← getElem!_pos path.val h hhpath, hp h hh]
    have hs := xmss_auth_leaf_schedule ⟨leaf, hleaf⟩ ⟨h, hh⟩
    simp only [xmssAuthLeafAt, Fin.val_mk] at hs
    obtain ⟨_, _, _, _, _, hsib, _, _⟩ := hs
    have hdiv : leaf / 2^h / 2 = leaf / 2^(h+1) := by
      rw [Nat.div_div_eq_div_mul, pow_succ]
    have hstep :
        (if (leaf / 2^h) % 2 = 0 then
          th_pair_pure seed (treeAdrs layer tree h (leaf / 2^h / 2))
            (pad16p (xmssRootNode seed sk layer tree h (leaf / 2^h)))
            (pad16p (xmssRootNode seed sk layer tree h (xmssAuthSibling leaf h)))
        else
          th_pair_pure seed (treeAdrs layer tree h (leaf / 2^h / 2))
            (pad16p (xmssRootNode seed sk layer tree h (xmssAuthSibling leaf h)))
            (pad16p (xmssRootNode seed sk layer tree h (leaf / 2^h)))) =
        xmssRootNode seed sk layer tree (h+1) (leaf / 2^(h+1)) := by
      by_cases heven : (leaf / 2^h) % 2 = 0
      · have hleft : leaf / 2^h = 2 * (leaf / 2^(h+1)) := by omega
        rw [if_pos heven, hsib, if_pos heven, hdiv, hleft, xmssRootNode]
      · have hright : leaf / 2^h = 2 * (leaf / 2^(h+1)) + 1 := by omega
        have hsib' : xmssAuthSibling leaf h = 2 * (leaf / 2^(h+1)) := by
          rw [hsib, if_neg heven, hright]
          omega
        rw [if_neg heven, hsib', hdiv, hright, xmssRootNode]
    rw [hd, authFold, hvalue, hstep, hdiv]
    simpa only [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using ih (h+1) (by omega)


theorem xmss_auth_recovery_root (seed sk : Std.Array Std.U8 32#usize)
    (layer leaf : Std.U32) (tree : Std.U64) (hleaf : leaf.val < 512)
    (node : Std.Array Std.U8 16#usize)
    (path : Std.Array (Std.Array Std.U8 16#usize) 9#usize)
    (hnode : node = wotsKeygenPure seed sk layer tree leaf)
    (hp : ∀ k, k < 9 → path.val[k]! = xmssRootNode seed sk layer tree k (xmssAuthSibling leaf.val k)) :
    authFold seed layer tree path.val node leaf.val 0 =
      xmssRootNode seed sk layer tree 9 0 := by
  have hlen : path.val.length = 9 := by simpa using path.property
  have hu : (⟨BitVec.ofNat 32 leaf.val⟩ : Std.U32) = leaf := by
    apply UScalar.eq_of_val_eq
    exact Nat.mod_eq_of_lt leaf.hBounds
  have hstart : node = xmssRootNode seed sk layer tree 0 leaf.val := by
    rw [xmssRootNode, hu, hnode]
  have hroot : leaf.val / 2^9 = 0 := Nat.div_eq_of_lt hleaf
  have h := xmss_auth_recovery_fold seed sk layer tree leaf.val hleaf path hp 9 0 (by decide)
  simpa only [List.drop_zero, List.take_of_length_le (by omega : path.val.length ≤ 9),
    Nat.zero_add, pow_zero, Nat.div_one, hroot, ← hstart] using h

/-- The actual path builder, WOTS public leaf, recovery and independent root
    builder terminate and agree. Complete WOTS signing and caller control flow
    remain outside this component theorem. -/
theorem firmware_xmss_build_recover_root (seed sk : Std.Array Std.U8 32#usize)
    (layer leaf : Std.U32) (tree : Std.U64)
    (progress : sphincs_c10.hypertree.ProgressSink) (pct_lo pct_hi : Std.U8)
    (hleaf : leaf.val < 512) :
    sphincs_c10.merkle.build_subtree_with_auth seed sk layer tree leaf progress pct_lo pct_hi ⦃ built =>
      sphincs_c10.wots.keygen_pk seed sk layer tree leaf ⦃ node =>
        sphincs_c10.merkle.verify_auth_path seed layer tree node leaf built.1 ⦃ recovered =>
          sphincs_c10.merkle.compute_subtree_root seed sk layer tree progress pct_lo pct_hi ⦃ expected =>
            recovered = built.2 ∧ recovered = expected ⦄ ⦄ ⦄ ⦄ := by
  let* ⟨path, root, hroot, hpath⟩ ← xmss_build_auth_spec seed sk layer leaf tree progress pct_lo pct_hi hleaf
  let* ⟨node, hnode⟩ ← wots_keygen_pk_spec seed sk layer tree leaf
  let* ⟨recovered, hr⟩ ← verify_auth_path_spec seed layer tree node leaf path
  let* ⟨expected, he⟩ ← xmss_compute_root_spec seed sk layer tree progress pct_lo pct_hi
  rw [hr, he, hroot, xmss_auth_recovery_root seed sk layer leaf tree hleaf node path hnode hpath]
  exact ⟨rfl, rfl⟩

theorem firmware_xmss_build_recover_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (layer leaf : Std.U32) (tree : Std.U64)
    (progress : sphincs_c10.hypertree.ProgressSink) (pct_lo pct_hi : Std.U8)
    (hleaf : leaf.val < 512) :
    sphincs_c10.merkle.build_subtree_with_auth seed sk layer tree leaf progress pct_lo pct_hi ⦃ built =>
      sphincs_c10.wots.keygen_pk seed sk layer tree leaf ⦃ node =>
        sphincs_c10.merkle.verify_auth_path seed layer tree node leaf built.1 ⦃ recovered =>
          toSpecNode recovered = SphincsCVerify.Spec.mtNode (toSpecDigest seed)
            (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
            (fun j => SphincsCVerify.Spec.Wots.keygenPk (toSpecDigest seed) (toSpecDigest sk)
              (UInt32.ofNat layer.val) (UInt64.ofNat tree.val) (UInt32.ofNat j)) 9 0 ⦄ ⦄ ⦄ := by
  let* ⟨path, root, hroot, hpath⟩ ← xmss_build_auth_spec seed sk layer leaf tree progress pct_lo pct_hi hleaf
  let* ⟨node, hnode⟩ ← wots_keygen_pk_spec seed sk layer tree leaf
  let* ⟨recovered, hr⟩ ← verify_auth_path_spec seed layer tree node leaf path
  rw [hr, xmss_auth_recovery_root seed sk layer leaf tree hleaf node path hnode hpath]
  exact xmss_root_node_matches_vendored seed sk layer tree 9 0 (by decide) (by decide)

end Extracted.Equiv
