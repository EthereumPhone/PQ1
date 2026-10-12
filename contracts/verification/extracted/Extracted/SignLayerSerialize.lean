/- Exact per-layer wire layout: 43 chains, all four big-endian counter bytes,
   then nine authentication siblings. The actual caller connection is separate. -/
import Extracted.SignWriteSpec
open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10
set_option maxHeartbeats 1000000
set_option maxRecDepth 8192

/-- Literal four-byte write fragment from the extracted signer layer. -/
def signerWriteCount (sig : C10Signature) (offset : Std.Usize) (count : Std.U32) :
    Result (C10Signature × Std.Usize) := do
  let next ← offset + 4#usize
  let (old,back) ← core.array.Array.index_mut (core.ops.index.IndexMutSlice
    (core.slice.index.SliceIndexRangeUsizeSlice Std.U8)) sig { start := offset, «end» := next }
  let a ← lift (core.num.U32.to_be_bytes count)
  let bytes ← lift (Array.to_slice a)
  let written ← core.slice.Slice.copy_from_slice core.marker.CopyU8 old bytes
  ok (back written,next)

@[step] theorem firmware_write_count (sig : C10Signature) (offset : Std.Usize)
    (count : Std.U32) (hb : offset.val+4 ≤ 4008) :
    signerWriteCount sig offset count ⦃ r => r.2.val = offset.val+4 ∧
      SignatureWrites sig r.1 offset.val 4
        (fun i => (core.num.U32.to_be_bytes count).val[i]!) ⦄ := by
  unfold signerWriteCount
  simp only [lift, bind_tc_ok]
  step* <;> first | scalar_tac | skip
  refine And.intro next_post ?_
  intro j
  rw [old_post3, written_post]
  simp only [Array.val_to_slice]
  have hs : sig.val.length = 4008 := by simp
  have hc : (core.num.U32.to_be_bytes count).val.length = 4 := by simp
  split <;> rename_i hj
  · exact List.getElem!_setSlice!_middle _ _ _ _ ⟨hj.1, by omega, by have := j.isLt; omega⟩
  · by_cases hp : j.val < offset.val
    · exact List.getElem!_setSlice!_prefix _ _ _ _ hp
    · exact List.getElem!_setSlice!_suffix _ _ _ _ (by omega)

theorem u32_be_roundtrip (count : Std.U32) :
    core.num.U32.from_be_bytes (core.num.U32.to_be_bytes count) = count := by
  apply UScalar.eq_of_val_eq
  simp only [UScalar.val, core.num.U32.from_be_bytes, core.num.U32.to_be_bytes,
    BitVec.toNat_cast, BitVec.fromBEBytes, BitVec.toBEBytes]
  have hm : (List.map U8.bv (count.bv.toLEBytes.reverse.map (@UScalar.mk .U8))).reverse =
      count.bv.toLEBytes := by
    simp only [List.map_map, Function.comp_def, U8.bv]
    change ((count.bv.toLEBytes.reverse).map id).reverse = _
    rw [List.map_id, List.reverse_reverse]
  exact (congrArg (fun bytes => (BitVec.fromLEBytes bytes).toNat) hm).trans
    (by rw [BitVec.fromLEBytes_toLEBytes (by decide : 32%8=0)]; rfl)

def layerBytes (chains : WotsChains) (count : Std.U32) (path : XmssAuth) (i : Nat) : Std.U8 :=
  if i < 688 then blockBytes (fun j => chains.val[j]!) i
  else if i < 692 then (core.num.U32.to_be_bytes count).val[i-688]!
  else blockBytes (fun j => path.val[j]!) (i-692)

def serializedLayer (sig : C10Signature) (base : Nat) (chains : WotsChains)
    (count : Std.U32) (path : XmssAuth) : C10Signature :=
  signatureOverwrite sig base 836 (layerBytes chains count path)

/-- Precisely the two loops and intervening count write in the actual layer. -/
def signerSerializeLayer (sig : C10Signature) (offset : Std.Usize)
    (chains : WotsChains) (count : Std.U32) (path : XmssAuth) :
    Result (C10Signature × Std.Usize) := do
  let (sig1,off1) ← hypertree.sign_inner_loop3_loop0 sig offset chains 0#usize
  let (sig2,off2) ← signerWriteCount sig1 off1 count
  hypertree.sign_inner_loop3_loop1 9#usize sig2 off2 path 0#usize

/-- Keep the caller's computed height as a parameter when factoring its body;
    the current constant instantiation is exactly the proven nine-row writer. -/
def signerSerializeLayerHeight (height : Std.Usize) (sig : C10Signature) (offset : Std.Usize)
    (chains : WotsChains) (count : Std.U32) (path : XmssAuth) :
    Result (C10Signature × Std.Usize) := do
  let (sig1,off1) ← hypertree.sign_inner_loop3_loop0 sig offset chains 0#usize
  let (sig2,off2) ← signerWriteCount sig1 off1 count
  hypertree.sign_inner_loop3_loop1 height sig2 off2 path 0#usize

theorem signerSerializeLayerHeight_nine (sig : C10Signature) (offset : Std.Usize)
    (chains : WotsChains) (count : Std.U32) (path : XmssAuth) :
    signerSerializeLayerHeight 9#usize sig offset chains count path =
      signerSerializeLayer sig offset chains count path := by rfl

@[step] theorem firmware_serialize_layer (sig : C10Signature) (offset : Std.Usize)
    (chains : WotsChains) (count : Std.U32) (path : XmssAuth)
    (hb : offset.val+836 ≤ 4008) :
    signerSerializeLayer sig offset chains count path ⦃ r =>
      r.2.val = offset.val+836 ∧ r.1 = serializedLayer sig offset.val chains count path ⦄ := by
  unfold signerSerializeLayer
  let* ⟨a,off1,ho1,hw1⟩ ← firmware_write_wots_chains sig offset chains (by omega)
  let* ⟨b,off2,ho2,hw2⟩ ← firmware_write_count a off1 count (by omega)
  let* ⟨out,off3,ho3,hw3⟩ ← firmware_write_xmss_path b off2 path (by omega)
  refine ⟨by omega, ?_⟩
  have first := signatureWrites_congr sig a offset.val 688 _ (layerBytes chains count path) hw1
    (fun i hi => by simp only [layerBytes, if_pos hi])
  have next := signatureWrites_congr a b off1.val 4 _
    (fun i => layerBytes chains count path (688+i)) hw2 (fun i hi => by
      simp only [layerBytes, if_neg (by omega : ¬688+i < 688), if_pos (by omega : 688+i < 692),
        Nat.add_sub_cancel_left])
  rw [ho1] at next
  have firstTwo := signatureWrites_append sig a b offset.val 688 4 (layerBytes chains count path) first next
  have last := signatureWrites_congr b out off2.val 144 _
    (fun i => layerBytes chains count path (692+i)) hw3 (fun i _ => by
      simp only [layerBytes, if_neg (by omega : ¬692+i < 688), if_neg (by omega : ¬692+i < 692),
        Nat.add_sub_cancel_left])
  have ho2' : off2.val = offset.val+692 := by omega
  rw [ho2'] at last
  have all := signatureWrites_append sig b out offset.val 692 144
    (layerBytes chains count path) firstTwo last
  exact signatureWrites_eq sig out offset.val 836 (layerBytes chains count path) all

theorem serializedLayer_chain (sig : C10Signature) (layer : Fin 2)
    (chains : WotsChains) (count : Std.U32) (path : XmssAuth) (t : Fin 43) :
    layerChainBytes (serializedLayer sig (2336+836*layer.val) chains count path) layer t =
      chains.val[t.val]! := by
  unfold layerChainBytes
  apply signatureNode_eq
  intro i
  have hl := layer.isLt
  have ht := t.isLt
  have hi := i.isLt
  have hpos : 2336+836*layer.val+16*t.val+i.val < 4008 := by omega
  have hw := signatureOverwrite_spec sig (2336+836*layer.val) 836 (layerBytes chains count path)
    ⟨2336+836*layer.val+16*t.val+i.val,hpos⟩
  dsimp only at hw
  unfold serializedLayer
  rw [hw, if_pos (by constructor <;> omega)]
  simp only [layerBytes,
    show 2336+836*layer.val+16*t.val+i.val-(2336+836*layer.val) = 16*t.val+i.val by omega,
    if_pos (by omega : 16*t.val+i.val < 688), blockBytes_at _ _ _ hi]

theorem serializedLayer_path (sig : C10Signature) (layer : Fin 2)
    (chains : WotsChains) (count : Std.U32) (path : XmssAuth) (t : Fin 9) :
    layerAuthBytes (serializedLayer sig (2336+836*layer.val) chains count path) layer t =
      path.val[t.val]! := by
  unfold layerAuthBytes
  apply signatureNode_eq
  intro i
  have hl := layer.isLt
  have ht := t.isLt
  have hi := i.isLt
  have hpos : 3028+836*layer.val+16*t.val+i.val < 4008 := by omega
  have hw := signatureOverwrite_spec sig (2336+836*layer.val) 836 (layerBytes chains count path)
    ⟨3028+836*layer.val+16*t.val+i.val,hpos⟩
  dsimp only at hw
  unfold serializedLayer
  rw [hw, if_pos (by constructor <;> omega)]
  simp only [layerBytes,
    show 3028+836*layer.val+16*t.val+i.val-(2336+836*layer.val) = 692+16*t.val+i.val by omega,
    if_neg (by omega : ¬692+16*t.val+i.val < 688), if_neg (by omega : ¬692+16*t.val+i.val < 692),
    show 692+16*t.val+i.val-692 = 16*t.val+i.val by omega, blockBytes_at _ _ _ hi]

/-- Every possible u32 counter survives serialization, including its upper bytes. -/
theorem serializedLayer_count (sig : C10Signature) (layer : Fin 2)
    (chains : WotsChains) (count : Std.U32) (path : XmssAuth) :
    parsedLayerCount (serializedLayer sig (2336+836*layer.val) chains count path) layer = count := by
  have he : layerCountBytes (serializedLayer sig (2336+836*layer.val) chains count path) layer =
      core.num.U32.to_be_bytes count := by
    apply fixedArray_ext
    intro j
    have hj : j.val < 4 := by simpa using j.isLt
    have hl := layer.isLt
    simp only [layerCountBytes, List.getElem!_ofFn _ _ hj]
    have hpos : 3024+836*layer.val+j.val < 4008 := by omega
    have hw := signatureOverwrite_spec sig (2336+836*layer.val) 836 (layerBytes chains count path)
      ⟨3024+836*layer.val+j.val,hpos⟩
    dsimp only at hw
    unfold serializedLayer
    rw [hw, if_pos (by constructor <;> omega)]
    simp only [layerBytes,
      show 3024+836*layer.val+j.val-(2336+836*layer.val) = 688+j.val by omega,
      if_neg (by omega : ¬688+j.val < 688), if_pos (by omega : 688+j.val < 692), Nat.add_sub_cancel_left]
  unfold parsedLayerCount
  rw [he, u32_be_roundtrip]

theorem serializedLayer_fields (sig : C10Signature) (layer : Fin 2)
    (chains : WotsChains) (count : Std.U32) (path : XmssAuth) :
    parsedLayerChains (serializedLayer sig (2336+836*layer.val) chains count path) layer = chains ∧
    parsedLayerCount (serializedLayer sig (2336+836*layer.val) chains count path) layer = count ∧
    parsedLayerAuth (serializedLayer sig (2336+836*layer.val) chains count path) layer = path := by
  refine ⟨?_, serializedLayer_count sig layer chains count path, ?_⟩
  · apply fixedArray_ext
    intro t
    rw [parsedLayerChains_get, serializedLayer_chain]
  · apply fixedArray_ext
    intro t
    rw [parsedLayerAuth_get, serializedLayer_path]

theorem serializedLayer_preserves (sig : C10Signature) (base : Nat)
    (chains : WotsChains) (count : Std.U32) (path : XmssAuth)
    (j : Fin 4008) (hj : j.val < base ∨ base+836 ≤ j.val) :
    (serializedLayer sig base chains count path).val[j.val]! = sig.val[j.val]! := by
  unfold serializedLayer
  rw [signatureOverwrite_spec sig base 836 (layerBytes chains count path) j, if_neg (by omega)]

theorem serialization_subtree_height : params.SUBTREE_H = .ok 9#usize := by
  have hv : params.SUBTREE_H ⦃ r => r = 9#usize ⦄ := by
    unfold params.SUBTREE_H
    simp only [params.H, params.D]
    step*
  obtain ⟨v,hr,hv⟩ := WP.spec_imp_exists hv
  simpa only [hv] using hr

theorem firmware_serialize_layer_at_params (sig : C10Signature) (offset : Std.Usize)
    (chains : WotsChains) (count : Std.U32) (path : XmssAuth)
    (hb : offset.val+836 ≤ 4008) :
    (do let height ← params.SUBTREE_H
        signerSerializeLayerHeight height sig offset chains count path) ⦃ r =>
      r.2.val = offset.val+836 ∧ r.1 = serializedLayer sig offset.val chains count path ⦄ := by
  rw [serialization_subtree_height]
  simpa only [bind_tc_ok, signerSerializeLayerHeight_nine] using
    firmware_serialize_layer sig offset chains count path hb

end Extracted.Equiv
