/- Actual XMSS authentication paths and roots agree with the reference tree. -/
import Extracted.XmssAuthSpec
import Extracted.XmssAuthVendored
import Extracted.XmssRootBridge

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 1500000
set_option maxRecDepth 8192
namespace Extracted.Equiv
open SphincsCVerify.Spec
attribute [local irreducible] xmssRootNode xmssRootSlots xmssAuthEnd xmssAuthSibling

theorem xmss_auth_path_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (layer leaf : Std.U32) (tree : Std.U64)
    (path : Std.Array (Std.Array Std.U8 16#usize) 9#usize)
    (hleaf : leaf.val < 512)
    (hp : ∀ k, k < 9 → path.val[k]! = xmssRootNode seed sk layer tree k (xmssAuthSibling leaf.val k)) :
    (path.val.map toSpecNode).toArray =
      mtAuthPath (toSpecDigest seed) (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
        (fun j => Wots.keygenPk (toSpecDigest seed) (toSpecDigest sk)
          (UInt32.ofNat layer.val) (UInt64.ofNat tree.val) (UInt32.ofNat j)) leaf.val := by
  have hlen : path.val.length = 9 := by simpa using path.property
  apply _root_.Array.ext
  · simp [hlen, mtAuthPath, SubtreeH]
  intro i hi1 hi2
  have hi : i < 9 := by simpa [hlen] using hi1
  simp only [mtAuthPath, _root_.Array.getElem_ofFn, List.getElem_toArray, List.getElem_map]
  rw [← getElem!_pos path.val i (by omega), hp i hi]
  have hsched := xmss_auth_leaf_schedule ⟨leaf.val, hleaf⟩ ⟨i, hi⟩
  simp only [xmssAuthLeafAt] at hsched
  obtain ⟨_, _, _, _, _, hsib, _, hfoot⟩ := hsched
  have hx := xmss_root_node_matches_vendored seed sk layer tree i (xmssAuthSibling leaf.val i)
    (by omega) hfoot
  simpa only [sibIdx, hsib] using hx

/-- Valid leaves, arbitrary seeds and full-width addresses; no desired-path or
    desired-root assumption. This remains a component of the full signer. -/
theorem firmware_xmss_auth_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (layer leaf : Std.U32) (tree : Std.U64)
    (progress : sphincs_c10.hypertree.ProgressSink) (pct_lo pct_hi : Std.U8)
    (hleaf : leaf.val < 512) :
    sphincs_c10.merkle.build_subtree_with_auth seed sk layer tree leaf progress pct_lo pct_hi ⦃ r =>
      toSpecNode r.2 = mtNode (toSpecDigest seed) (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
        (fun j => Wots.keygenPk (toSpecDigest seed) (toSpecDigest sk)
          (UInt32.ofNat layer.val) (UInt64.ofNat tree.val) (UInt32.ofNat j)) 9 0 ∧
      (r.1.val.map toSpecNode).toArray =
        mtAuthPath (toSpecDigest seed) (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
          (fun j => Wots.keygenPk (toSpecDigest seed) (toSpecDigest sk)
            (UInt32.ofNat layer.val) (UInt64.ofNat tree.val) (UInt32.ofNat j)) leaf.val ⦄ := by
  let* ⟨path, root, hroot, hpath⟩ ← xmss_build_auth_spec seed sk layer leaf tree progress pct_lo pct_hi hleaf
  constructor
  · rw [hroot]
    exact xmss_root_node_matches_vendored seed sk layer tree 9 0 (by decide) (by decide)
  · exact xmss_auth_path_matches_vendored seed sk layer leaf tree path hleaf hpath

end Extracted.Equiv
