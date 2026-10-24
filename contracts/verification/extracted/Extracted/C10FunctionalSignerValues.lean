/- Sequential signer values under the shared deterministic backend. Failure
   remains an endpoint Result; it is never an assumed successful search. -/
import Extracted.C10FunctionalSignerHeader
import Extracted.C10FunctionalSignatureBytes
import Extracted.C10FunctionalLayer
import Extracted.C10FunctionalVerifier
import Extracted.SignReleaseSpec

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge Extracted.C10RepresentationBridge C10Representation
open Extracted.C10FunctionalWots Extracted.C10FunctionalForest Extracted.C10FunctionalLayer
open Extracted.C10FunctionalSignerHeader Extracted.C10FunctionalSignatureBytes
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes
attribute [local irreducible] List.range C10Representation.layer_sign_slot

namespace Extracted.C10FunctionalSignerValues

def layerResult (f : List Int → List Int) (seed secret : List Int)
    (layer tree leaf : Int) (message : List Int) : Result (WordLayer × List Int) :=
  let slot := layer_sign_slot f seed layer tree leaf message
  if slot = 0 then .fail .assertionFailure else
    let sig := layer_sign_values f seed secret layer tree leaf message (Int.ofNat (slot-1))
    .ok (sig, layer_recover_value f seed layer tree leaf message sig.1 sig.2.1 sig.2.2)

def finishResult (f : List Int → List Int) (seed secret random digest : List Int) :
    Result WordSignature := do
  let ht := ht_field digest
  let forest := forest_sign_value f seed secret ht (digest_fors_indices digest)
  let (first,current) ← layerResult f seed secret 0 (ht/512) (ht%512) forest.2.2
  let (second,_) ← layerResult f seed secret 1 (ht/512/512) (ht/512%512) current
  .ok (random,forest.1,forest.2.1,[first,second])

def signerResult (f : List Int → List Int) (seed root secret random message : List Int) :
    Result WordSignature := do
  let (nonce,digest) ← headerResult f seed root secret random message
  finishResult f seed secret nonce digest

theorem pure_layer_result (seed secret : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Std.U32) (hl : leaf.val < 512)
    (message : Std.Array Std.U8 16#usize) (progress : sphincs_c10.hypertree.ProgressSink) :
    (do let (chains,count) ← Equiv.pureWotsSign seed secret layer tree leaf message
        .ok ((nodeWords chains,Int.ofNat count.val,
          nodeWords (Equiv.xmssSigningPath seed secret layer tree leaf)),
          byteInts (Equiv.xmssRootNode seed secret layer tree 9 0).val)) =
      layerResult suppliedBackend (byteInts seed.val) (byteInts secret.val)
        (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat leaf.val) (byteInts message.val) := by
  rcases pure_layer_sign_values seed secret layer tree leaf hl message progress with
    ⟨chains,count,hs,hc,hslot,hfields⟩ | ⟨hs,hslot⟩
  · simp only [layerResult, hs, hslot, bind_tc_ok, uncurry_apply_pair,
      Nat.add_sub_cancel, Nat.add_eq_zero_iff, Nat.one_ne_zero, and_false, if_false]
    rw [← hfields, signed_layer_recovery_value seed secret layer tree leaf hl message chains count hs]
  · simp only [layerResult, hs, hslot, bind_tc_fail, if_true]

theorem layer_coordinates (idx : Std.U32) (layer : Fin 2) :
    (Equiv.signLayerId layer).val = layer.val ∧
    (UScalar.cast .U64 (Equiv.signNextTree idx)).val = idx.val/512 ∧
    (Equiv.signLeaf idx).val = idx.val%512 := by
  refine ⟨?_, ?_, Equiv.sign_leaf_val idx⟩
  · change layer.val % 4294967296 = layer.val
    exact Nat.mod_eq_of_lt (by have := layer.isLt; omega)
  · rw [UScalar.cast_val_eq, Equiv.sign_next_tree_val]
    change (idx.val/512) % 18446744073709551616 = idx.val/512
    exact Nat.mod_eq_of_lt (by have h : idx.val < 4294967296 := idx.hBounds; omega)

theorem indexed_layer_result (seed secret : Std.Array Std.U8 32#usize)
    (layer : Fin 2) (idx : Std.U32) (message : Std.Array Std.U8 16#usize)
    (progress : sphincs_c10.hypertree.ProgressSink) :
    (do let (chains,count) ← Equiv.pureWotsSign seed secret (Equiv.signLayerId layer)
          (UScalar.cast .U64 (Equiv.signNextTree idx)) (Equiv.signLeaf idx) message
        .ok ((nodeWords chains,Int.ofNat count.val,
          nodeWords (Equiv.xmssSigningPath seed secret (Equiv.signLayerId layer)
            (UScalar.cast .U64 (Equiv.signNextTree idx)) (Equiv.signLeaf idx))),
          byteInts (Equiv.xmssRootNode seed secret (Equiv.signLayerId layer)
            (UScalar.cast .U64 (Equiv.signNextTree idx)) 9 0).val)) =
      layerResult suppliedBackend (byteInts seed.val) (byteInts secret.val)
        (Int.ofNat layer.val) (Int.ofNat idx.val/512) (Int.ofNat idx.val%512) (byteInts message.val) := by
  have h := pure_layer_result seed secret (Equiv.signLayerId layer)
    (UScalar.cast .U64 (Equiv.signNextTree idx)) (Equiv.signLeaf idx)
    (by rw [Equiv.sign_leaf_val]; omega) message progress
  have co := layer_coordinates idx layer
  rw [co.1,co.2.1,co.2.2] at h
  simpa only [Int.ofNat_eq_natCast, Int.natCast_ediv, Int.natCast_emod, Nat.cast_ofNat] using h

theorem second_indexed_layer_result (seed secret : Std.Array Std.U8 32#usize)
    (idx : Std.U32) (message : Std.Array Std.U8 16#usize)
    (progress : sphincs_c10.hypertree.ProgressSink) :
    (do let (chains,count) ← Equiv.pureWotsSign seed secret (Equiv.signLayerId ⟨1,by decide⟩)
          (UScalar.cast .U64 (Equiv.signNextTree (Equiv.signNextTree idx))) (Equiv.signLeaf (Equiv.signNextTree idx)) message
        .ok ((nodeWords chains,Int.ofNat count.val,
          nodeWords (Equiv.xmssSigningPath seed secret (Equiv.signLayerId ⟨1,by decide⟩)
            (UScalar.cast .U64 (Equiv.signNextTree (Equiv.signNextTree idx))) (Equiv.signLeaf (Equiv.signNextTree idx)))),
          byteInts (Equiv.xmssRootNode seed secret (Equiv.signLayerId ⟨1,by decide⟩)
            (UScalar.cast .U64 (Equiv.signNextTree (Equiv.signNextTree idx))) 9 0).val)) =
      layerResult suppliedBackend (byteInts seed.val) (byteInts secret.val)
        1 (Int.ofNat idx.val/512/512) (Int.ofNat idx.val/512%512) (byteInts message.val) := by
  have h := indexed_layer_result seed secret ⟨1,by decide⟩ (Equiv.signNextTree idx) message progress
  simpa only [Equiv.sign_next_tree_val, Int.ofNat_eq_natCast, Int.natCast_ediv,
    Int.natCast_emod, Nat.cast_ofNat, Int.natCast_one] using h

end Extracted.C10FunctionalSignerValues
