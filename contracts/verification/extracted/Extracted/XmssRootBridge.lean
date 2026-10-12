/- Actual XMSS root construction and top-level key generation. -/
import Extracted.XmssRootSpec
import Extracted.XmssRootVendored
import Extracted.WotsKeygenBridge
import Extracted.MerkleRecoveryBridge

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 1500000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open SphincsCVerify.Spec
attribute [local irreducible] thPair Adrs.treeNode ByteVec.pad16

theorem xmss_root_node_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (h idx : Nat) (hh : h ≤ 9)
    (hi : (idx+1)*2^h ≤ 512) :
    toSpecNode (xmssRootNode seed sk layer tree h idx) =
      mtNode (toSpecDigest seed) (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
        (fun j => Wots.keygenPk (toSpecDigest seed) (toSpecDigest sk)
          (UInt32.ofNat layer.val) (UInt64.ofNat tree.val) (UInt32.ofNat j)) h idx := by
  have hidx : idx < 2^32 := by
    have hp : 0 < 2^h := by positivity
    nlinarith
  induction h generalizing idx with
  | zero =>
    rw [xmssRootNode, mtNode, wots_keygen_pure_matches_vendored]
    have hv : (⟨BitVec.ofNat 32 idx⟩ : Std.U32).val = idx := Nat.mod_eq_of_lt hidx
    rw [hv]
  | succ h ih =>
    rw [xmssRootNode, mtNode, merkle_th_pair,
      merkle_tree_adrs _ _ _ _ (by omega) hidx, merkle_pad, merkle_pad]
    have hpow : 2^(h+1) = 2^h * 2 := by rw [pow_succ]
    rw [hpow] at hi
    have hp : 0 < 2^h := by positivity
    rw [ih (2*idx) (by omega) (by nlinarith) (by nlinarith),
      ih (2*idx+1) (by omega) (by nlinarith) (by nlinarith)]

/-- Callback-free extraction: all seeds, full-width layer/tree positions and progress ranges. -/
theorem firmware_xmss_root_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (progress : sphincs_c10.hypertree.ProgressSink)
    (pct_lo pct_hi : Std.U8) :
    sphincs_c10.merkle.compute_subtree_root seed sk layer tree progress pct_lo pct_hi ⦃ r =>
      toSpecNode r = mtNode (toSpecDigest seed) (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
        (fun j => Wots.keygenPk (toSpecDigest seed) (toSpecDigest sk)
          (UInt32.ofNat layer.val) (UInt64.ofNat tree.val) (UInt32.ofNat j)) SubtreeH 0 ⦄ := by
  let* ⟨r, hr⟩ ← xmss_compute_root_spec seed sk layer tree progress pct_lo pct_hi
  rw [hr]
  exact xmss_root_node_matches_vendored seed sk layer tree 9 0 (by decide) (by decide)

/-- Actual public-key root: padded public seed, layer one, tree zero, height nine. -/
theorem firmware_pk_root_matches_vendored (sk : Std.Array Std.U8 32#usize)
    (seed : Std.Array Std.U8 16#usize) :
    sphincs_c10.hypertree.compute_pk_root sk seed ⦃ r =>
      toSpecNode r = mtNode (ByteVec.pad16 (toSpecNode seed)) 1 0
        (fun j => Wots.keygenPk (ByteVec.pad16 (toSpecNode seed)) (toSpecDigest sk)
          1 0 (UInt32.ofNat j)) SubtreeH 0 ⦄ := by
  let* ⟨r, hr⟩ ← xmss_compute_pk_root_spec sk seed
  rw [hr, xmss_root_node_matches_vendored _ _ _ _ _ _ (by decide) (by decide), merkle_pad]
  rfl

end Extracted.Equiv
