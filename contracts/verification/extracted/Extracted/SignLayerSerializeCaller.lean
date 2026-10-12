/- Kernel equality connects the proven serializer to the actual signer layer.
   Cryptographic computation and all Result failures remain unchanged. -/
import Extracted.SignLayerSerialize
open Aeneas Aeneas.Std Result ControlFlow Error
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 200000
set_option maxRecDepth 8192
attribute [local irreducible] merkle.build_subtree_with_auth wots.sign_with_shuffle
  wots.pk_from_sig merkle.verify_auth_path sphincs_c10.shuffle.ShuffleSeed.derive
  hypertree.sign_inner_loop3_loop0 hypertree.sign_inner_loop3_loop1

abbrev SignLayerResult := ControlFlow ((core.ops.range.Range Std.U32) × C10Signature × Std.Usize × (Std.Array Std.U8 16#usize) × Std.U32) (C10Signature × Std.Usize × (Std.Array Std.U8 16#usize))
abbrev LayerSerialization := Std.Usize → C10Signature → Std.Usize → WotsChains → Std.U32 → XmssAuth → ((C10Signature × Std.Usize) → Result SignLayerResult) → Result SignLayerResult

def literalLayerSerialization : LayerSerialization := fun height sig offset chains count path continuation => do
    let (sig1, offset1) ←
      hypertree.sign_inner_loop3_loop0 sig offset chains 0#usize
    let i10 ← offset1 + 4#usize
    let (s1, index_mut_back) ←
      core.array.Array.index_mut (core.ops.index.IndexMutSlice
        (core.slice.index.SliceIndexRangeUsizeSlice Std.U8)) sig1
        { start := offset1, «end» := i10 }
    let a ← lift (core.num.U32.to_be_bytes count)
    let s2 ← lift (Array.to_slice a)
    let s3 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s1 s2
    let sig2 := index_mut_back s3
    let result ← hypertree.sign_inner_loop3_loop1 height sig2 i10 path 0#usize
    continuation result

def provenLayerSerialization : LayerSerialization := fun height sig offset chains count path continuation => do
  let result ← signerSerializeLayerHeight height sig offset chains count path
  continuation result

def signerLayerUsingSerialization (serialize : LayerSerialization)
  (sk_seed : Array Std.U8 32#usize) (progress : hypertree.ProgressSink)
  (shuffle : shuffle.ShuffleSeed) (seed : Array Std.U8 32#usize)
  (iter : core.ops.range.Range Std.U32) (sig : Array Std.U8 4008#usize)
  (offset : Std.Usize) (current_node : Array Std.U8 16#usize)
  (idx_tree : Std.U32) :
  Result (ControlFlow ((core.ops.range.Range Std.U32) × (Array Std.U8
    4008#usize) × Std.Usize × (Array Std.U8 16#usize) × Std.U32) ((Array
    Std.U8 4008#usize) × Std.Usize × (Array Std.U8 16#usize)))
  := do
  let (o, iter1) ←
    core.iter.range.IteratorRange.next U32.Insts.CoreIterRangeStep iter
  match o with
  | none => ok (done (sig, offset, current_node))
  | some layer =>
    let i ← params.SUBTREE_H
    let i1 ← 1#u32 <<< i
    let i2 ← i1 - 1#u32
    let idx_leaf ← lift (idx_tree &&& i2)
    let idx_tree1 ← idx_tree >>> i
    let i3 ← layer * 33#u32
    let i4 ← 32#u32 + i3
    let pct_lo ← lift (UScalar.cast .U8 i4)
    let i5 ← layer + 1#u32
    let i6 ← i5 * 33#u32
    let i7 ← 32#u32 + i6
    let pct_hi ← lift (UScalar.cast .U8 i7)
    let i8 ← lift (UScalar.cast .U64 idx_tree1)
    let (auth_path, _) ←
      merkle.build_subtree_with_auth seed sk_seed layer i8 idx_leaf progress
        pct_lo pct_hi
    hypertree.report progress pct_hi
    let wots_label ←
      match layer with
      | 0#uscalar =>
        ok
          (Array.make 7#usize [
             119#u8, 111#u8, 116#u8, 115#u8, 45#u8, 48#u8, 0#u8
             ] : Array Std.U8 7#usize)
      | _ =>
        ok
          (Array.make 7#usize [
             119#u8, 111#u8, 116#u8, 115#u8, 45#u8, 49#u8, 0#u8
             ] : Array Std.U8 7#usize)
    let s ← lift (Array.to_slice wots_label)
    let wots_shuffle_seed ← sphincs_c10.shuffle.ShuffleSeed.derive shuffle s
    let i9 ← lift (UScalar.cast .U64 idx_tree1)
    let (wots_sigma, count) ←
      wots.sign_with_shuffle seed sk_seed layer i9 idx_leaf current_node
        wots_shuffle_seed progress pct_hi
    serialize i sig offset wots_sigma count auth_path (uncurry fun sig3 offset2 => do
    let i11 ← lift (UScalar.cast .U64 idx_tree1)
    let wots_pk ←
      wots.pk_from_sig seed layer i11 idx_leaf current_node wots_sigma count
    let i12 ← lift (UScalar.cast .U64 idx_tree1)
    let current_node1 ←
      merkle.verify_auth_path seed layer i12 wots_pk idx_leaf auth_path
    ok (cont (iter1, sig3, offset2, current_node1, idx_tree1)))


def signerLayerWithSerializedFields := signerLayerUsingSerialization provenLayerSerialization

theorem signerSerializeLayer_bind {α : Type} (height : Std.Usize) (sig : C10Signature) (offset : Std.Usize)
    (chains : WotsChains) (count : Std.U32) (path : XmssAuth)
    (continuation : (C10Signature × Std.Usize) → Result α) :
    (do
    let (sig1, offset1) ←
      hypertree.sign_inner_loop3_loop0 sig offset chains 0#usize
    let i10 ← offset1 + 4#usize
    let (s1, index_mut_back) ←
      core.array.Array.index_mut (core.ops.index.IndexMutSlice
        (core.slice.index.SliceIndexRangeUsizeSlice Std.U8)) sig1
        { start := offset1, «end» := i10 }
    let a ← lift (core.num.U32.to_be_bytes count)
    let s2 ← lift (Array.to_slice a)
    let s3 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s1 s2
    let sig2 := index_mut_back s3
    let result ← hypertree.sign_inner_loop3_loop1 height sig2 i10 path 0#usize
    continuation result) = (do
      let result ← signerSerializeLayerHeight height sig offset chains count path
      continuation result) := by
  simp only [signerSerializeLayerHeight, signerWriteCount, bind_assoc_eq]
  rw [bind_eq_iff]
  rintro ⟨out,off⟩ _
  simp only [uncurry_apply_pair, bind_assoc_eq, bind_eq_iff]
  intro next hnext
  rintro ⟨slice,back⟩ hslice
  simp only [uncurry_apply_pair, bind_assoc_eq, bind_tc_ok]

theorem layerSerialization_eq : literalLayerSerialization = provenLayerSerialization := by
  funext height sig offset chains count path continuation
  exact signerSerializeLayer_bind height sig offset chains count path continuation

-- Explicit diagnostics avoid re-normalizing this entire body just to locate
-- a mismatch after a mutation. This changes printing, not proof checking.
set_option pp.explicit true in
theorem signer_layer_serialization_factor
    (sk seed : Std.Array Std.U8 32#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) (iter : core.ops.range.Range Std.U32)
    (sig : C10Signature) (offset : Std.Usize) (node : Std.Array Std.U8 16#usize) (tree : Std.U32) :
    hypertree.sign_inner_loop3.body sk progress shuffle seed iter sig offset node tree =
      signerLayerWithSerializedFields sk progress shuffle seed iter sig offset node tree := by
  calc
    _ = signerLayerUsingSerialization literalLayerSerialization sk progress shuffle seed iter sig offset node tree := by
      unfold hypertree.sign_inner_loop3.body signerLayerUsingSerialization literalLayerSerialization
      delta Aeneas.Std.uncurry
      -- Lean may share generated matcher declarations across cloned definitions.
      try delta hypertree.sign_inner_loop3.body.match_1
      try delta hypertree.sign_inner_loop3.body.match_3
      try delta signerLayerUsingSerialization.match_1
      try delta signerLayerUsingSerialization.match_3
      with_reducible rfl
    _ = _ := by rw [layerSerialization_eq]; rfl

end
end Extracted.Equiv
