/- Actual layer computation and recovery under the existing supplied backend.
   The bounded search failure is retained; no success hypothesis is imposed. -/
import Extracted.C10FunctionalForest
import Extracted.C10FunctionalWotsRecover
import Extracted.SignHypertreeLayer

open Aeneas Aeneas.Std Result ControlFlow
open Extracted.C10HashInputBridge C10Representation
open Extracted.C10FunctionalWots Extracted.C10FunctionalTrees
open Extracted.C10FunctionalBuilders Extracted.C10FunctionalForest
open Extracted.C10FunctionalWotsSign Extracted.C10FunctionalWotsRecover
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes
-- Keep the finite schedule symbolic during endpoint unification. A changed
-- bound or sentinel must fail normally, not expand ten million list cells.
attribute [local irreducible] List.range C10Representation.wots_first_slot

namespace Extracted.C10FunctionalLayer

theorem layer_path_value (seed sk : Std.Array Std.U8 32#usize)
    (layer leaf : Std.U32) (tree : Std.U64) (hl : leaf.val < 512) :
    nodeWords (Equiv.xmssSigningPath seed sk layer tree leaf) =
      merkle_auth_values suppliedBackend (byteInts seed.val) (byteInts sk.val)
        (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat leaf.val) := by
  exact merkle_path_value seed sk layer leaf tree _ hl
    (Equiv.xmss_signing_path_get seed sk layer tree leaf)

theorem layer_recovery_value (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Std.U32)
    (message : Std.Array Std.U8 16#usize) (chains : Equiv.WotsChains) (count : Std.U32)
    (path : Equiv.XmssAuth) :
    (do let pk ← sphincs_c10.wots.pk_from_sig seed layer tree leaf message chains count
        sphincs_c10.merkle.verify_auth_path seed layer tree pk leaf path) ⦃ r =>
      byteInts r.val = layer_recover_value suppliedBackend (byteInts seed.val)
        (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat leaf.val) (byteInts message.val)
        (nodeWords chains) (Int.ofNat count.val) (nodeWords path) ⦄ := by
  let* ⟨pk, hp⟩ ← extracted_recover_value seed layer tree leaf message chains count
  let* ⟨root, hr⟩ ← extracted_merkle_recover_value seed layer tree pk leaf path
  rw [hr, hp]
  rfl

theorem signed_layer_recovery_value (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Std.U32) (hl : leaf.val < 512)
    (message : Std.Array Std.U8 16#usize) (chains : Equiv.WotsChains) (count : Std.U32)
    (hs : Equiv.pureWotsSign seed sk layer tree leaf message = .ok (chains,count)) :
    byteInts (Equiv.xmssRootNode seed sk layer tree 9 0).val =
      layer_recover_value suppliedBackend (byteInts seed.val)
        (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat leaf.val) (byteInts message.val)
        (nodeWords chains) (Int.ofNat count.val)
        (nodeWords (Equiv.xmssSigningPath seed sk layer tree leaf)) := by
  have hv := layer_recovery_value seed layer tree leaf message chains count
    (Equiv.xmssSigningPath seed sk layer tree leaf)
  rw [Equiv.pure_wots_recovery seed sk layer tree leaf message chains count hs] at hv
  simp only [bind_tc_ok] at hv
  rw [Equiv.xmss_signing_path_recovery seed sk layer tree leaf hl] at hv
  simpa only [WP.spec_ok] using hv

theorem pure_layer_sign_values (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Std.U32) (hl : leaf.val < 512)
    (message : Std.Array Std.U8 16#usize) (progress : sphincs_c10.hypertree.ProgressSink) :
    (∃ (chains : Equiv.WotsChains) (count : Std.U32),
      Equiv.pureWotsSign seed sk layer tree leaf message = .ok (chains,count) ∧
      count.val < 10000000 ∧
      layer_sign_slot suppliedBackend (byteInts seed.val) (Int.ofNat layer.val)
        (Int.ofNat tree.val) (Int.ofNat leaf.val) (byteInts message.val) = count.val+1 ∧
      (nodeWords chains, Int.ofNat count.val,
        nodeWords (Equiv.xmssSigningPath seed sk layer tree leaf)) =
        layer_sign_values suppliedBackend (byteInts seed.val) (byteInts sk.val)
          (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat leaf.val)
          (byteInts message.val) (Int.ofNat count.val)) ∨
    (Equiv.pureWotsSign seed sk layer tree leaf message = .fail .assertionFailure ∧
      layer_sign_slot suppliedBackend (byteInts seed.val) (Int.ofNat layer.val)
        (Int.ofNat tree.val) (Int.ofNat leaf.val) (byteInts message.val) = 0) := by
  have hv := extracted_sign_value seed sk layer tree leaf message
    (Std.Array.repeat 32#usize 0#u8) progress 0#u8
  rw [Equiv.firmware_wots_sign_pure] at hv
  rcases hv with ⟨chains, count, hs, hc, hslot, hchains⟩ | ⟨hs, hslot⟩
  · refine Or.inl ⟨chains, count, hs, hc, hslot, ?_⟩
    unfold layer_sign_values
    rw [layer_path_value seed sk layer leaf tree hl]
    change (chains.val.map (fun v => byteInts v.val), _, _) = _
    rw [hchains]
  · exact Or.inr ⟨hs, hslot⟩

/-- The actual extracted loop body, including the serialized continuation and
    assertion-failure branch, consumes the shared fields and recovered root. -/
theorem extracted_layer_body_values (sk seed : Std.Array Std.U8 32#usize)
    (progress : sphincs_c10.hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig : Equiv.C10Signature) (message : Std.Array Std.U8 16#usize)
    (idx : Std.U32) (layer : Fin 2) :
    let lid := Equiv.signLayerId layer
    let tree := UScalar.cast .U64 (Equiv.signNextTree idx)
    let leaf := Equiv.signLeaf idx
    (∃ (chains : Equiv.WotsChains) (count : Std.U32),
      sphincs_c10.hypertree.sign_inner_loop3.body sk progress shuffle seed
        (Equiv.signIteration layer.val) sig (Equiv.signOffset layer.val) message idx =
        .ok (.cont (Equiv.signIteration (layer.val+1),
          Equiv.serializedLayer sig (2336+836*layer.val) chains count
            (Equiv.xmssSigningPath seed sk lid tree leaf),
          Equiv.signOffset (layer.val+1), Equiv.xmssRootNode seed sk lid tree 9 0,
          Equiv.signNextTree idx)) ∧
      count.val < 10000000 ∧
      layer_sign_slot suppliedBackend (byteInts seed.val) (Int.ofNat lid.val)
        (Int.ofNat tree.val) (Int.ofNat leaf.val) (byteInts message.val) = count.val+1 ∧
      (nodeWords chains, Int.ofNat count.val, nodeWords (Equiv.xmssSigningPath seed sk lid tree leaf)) =
        layer_sign_values suppliedBackend (byteInts seed.val) (byteInts sk.val)
          (Int.ofNat lid.val) (Int.ofNat tree.val) (Int.ofNat leaf.val)
          (byteInts message.val) (Int.ofNat count.val) ∧
      byteInts (Equiv.xmssRootNode seed sk lid tree 9 0).val =
        layer_recover_value suppliedBackend (byteInts seed.val) (Int.ofNat lid.val)
          (Int.ofNat tree.val) (Int.ofNat leaf.val) (byteInts message.val)
          (nodeWords chains) (Int.ofNat count.val) (nodeWords (Equiv.xmssSigningPath seed sk lid tree leaf))) ∨
    (sphincs_c10.hypertree.sign_inner_loop3.body sk progress shuffle seed
        (Equiv.signIteration layer.val) sig (Equiv.signOffset layer.val) message idx = .fail .assertionFailure ∧
      layer_sign_slot suppliedBackend (byteInts seed.val) (Int.ofNat lid.val)
        (Int.ofNat tree.val) (Int.ofNat leaf.val) (byteInts message.val) = 0) := by
  dsimp only
  have hl : (Equiv.signLeaf idx).val < 512 := by
    rw [Equiv.sign_leaf_val]; exact Nat.mod_lt _ (by decide)
  rcases pure_layer_sign_values seed sk (Equiv.signLayerId layer)
      (UScalar.cast .U64 (Equiv.signNextTree idx)) (Equiv.signLeaf idx) hl message progress with
    ⟨chains, count, hs, hc, hslot, hfields⟩ | ⟨hs, hslot⟩
  · refine Or.inl ⟨chains, count, ?_, hc, hslot, hfields, ?_⟩
    · rw [Equiv.firmware_sign_layer_body, Equiv.pureSignLayer, hs]
      rfl
    · exact signed_layer_recovery_value seed sk _ _ _ hl message chains count hs
  · refine Or.inr ⟨?_, hslot⟩
    rw [Equiv.firmware_sign_layer_body, Equiv.pureSignLayer, hs]
    rfl

end Extracted.C10FunctionalLayer
