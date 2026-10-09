/- Connect the complete faithful byte decoder to the actual parser values. -/
import Extracted.HypertreeStrictSpec
import Extracted.SignatureDecodeVendored
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10 SphincsCVerify.Spec
set_option maxHeartbeats 200000
set_option maxRecDepth 8192

def toSpecSignatureBytes (sig : C10Signature) : ByteVec SignatureLen :=
  ⟨(sig.val.map (fun x : Std.U8 => UInt8.ofNat x.val)).toArray, by simp only [List.size_toArray, List.length_map, sig.property]; rfl⟩

private theorem specByteVec_ext {n : Nat} (a b : ByteVec n)
    (h : a.data = b.data) : a = b := by
  cases a; cases b; cases h; rfl

attribute [local irreducible] _root_.Array.extract _root_.Array.replicate

/-- Sixteen-byte loads retain in-range bytes even if the 32-byte load overruns. -/
theorem loadValue16_data {n : Nat} (bytes : ByteVec n) (offset : Nat)
    (h : offset + 16 ≤ n) :
    (ByteVec.loadValue16 bytes offset).data = bytes.data.extract offset (offset+16) := by
  unfold ByteVec.loadValue16 ByteVec.take ByteVec.loadWord32
  apply _root_.Array.toList_inj.mp
  simp only [_root_.Array.toList_extract, _root_.Array.toList_append,
    _root_.Array.toList_replicate, List.extract_eq_take_drop,
    Nat.sub_zero, List.drop_zero, Nat.add_sub_cancel_left]
  rw [List.take_take, show min 16 32 = 16 from by decide]
  have hl : 16 ≤ (List.take 32 (List.drop offset bytes.data.toList)).length := by
    simp only [List.length_take, List.length_drop, _root_.Array.length_toList, bytes.size_eq]
    omega
  rw [List.take_append_of_le_length hl, List.take_take, show min 16 32 = 16 from by decide]


/-- This includes the final node at offset 3992, whose 32-byte load overruns. -/
theorem loadValue16_signatureNode (sig : C10Signature) (offset : Fin 3993) :
    ByteVec.loadValue16 (toSpecSignatureBytes sig) offset.val =
      toSpecNode (signatureNode sig offset) := by
  apply specByteVec_ext
  rw [loadValue16_data _ _ (by change offset.val + 16 ≤ 4008; have := offset.isLt; omega)]
  simp only [toSpecSignatureBytes, toSpecNode, signatureNode, List.extract_toArray,
    List.extract_eq_take_drop, List.slice, Nat.add_sub_cancel_left,
    List.map_take, List.map_drop]

def parsedSignature (sig : C10Signature) : Hypertree.Signature :=
  { r := toSpecNode (verifierRandomizer sig)
    fors := toSpecForsSig (parsedForsSecrets sig) (parsedForsAuth sig)
    layers := parsedHypertreeLayers sig
    layersLen := by rfl }

theorem deserialise_randomizer (sig : C10Signature) :
    (Signature.deserialise (toSpecSignatureBytes sig)).r =
      (parsedSignature sig).r := by
  change ByteVec.loadValue16 (toSpecSignatureBytes sig) 0 = toSpecNode (verifierRandomizer sig)
  rw [loadValue16_signatureNode sig ⟨0, by decide⟩]
  rfl

theorem deserialise_fors (sig : C10Signature) :
    (Signature.deserialise (toSpecSignatureBytes sig)).fors =
      (parsedSignature sig).fors := by
  simp only [Signature.deserialise, parsedSignature, toSpecForsSig,
    parsedForsSecrets, parsedForsAuth, List.map_ofFn, List.toArray_ofFn]
  congr 1
  · apply congrArg _root_.Array.ofFn
    funext t
    change ByteVec.loadValue16 (toSpecSignatureBytes sig) (16+t.val*16) =
      toSpecNode (forsSecretBytes sig t)
    simpa only [forsSecretBytes, Nat.mul_comm] using
      loadValue16_signatureNode sig ⟨16+16*t.val, by
        have ht : t.val < 13 := by simpa only [K] using t.isLt
        omega⟩
  · apply congrArg _root_.Array.ofFn
    funext t
    simp only [Function.comp_apply, List.map_ofFn, List.toArray_ofFn]
    apply congrArg _root_.Array.ofFn
    funext h
    change ByteVec.loadValue16 (toSpecSignatureBytes sig) (224+t.val*176+h.val*16) =
      toSpecNode (forsAuthBytes sig t h)
    simpa only [forsAuthBytes, Nat.mul_comm] using
      loadValue16_signatureNode sig ⟨224+176*t.val+16*h.val, by
        have ht : t.val < 12 := by simpa only [K] using t.isLt
        have hh : h.val < 11 := by simpa only [A] using h.isLt
        omega⟩

theorem uint32_be_val (a b c d : UInt8) :
    ((UInt32.ofNat a.toNat <<< 24) ||| (UInt32.ofNat b.toNat <<< 16) |||
      (UInt32.ofNat c.toNat <<< 8) ||| UInt32.ofNat d.toNat).toNat =
      a.toNat*16777216 + b.toNat*65536 + c.toNat*256 + d.toNat := by
  have ha := a.toNat_lt
  have hb := b.toNat_lt
  have hc := c.toNat_lt
  have hd := d.toNat_lt
  simp only [UInt32.toNat_or, UInt32.toNat_shiftLeft, UInt32.toNat_ofNat']
  have ha24 : a.toNat <<< 24 < 2^32 := by rw [Nat.shiftLeft_eq]; omega
  have hb16 : b.toNat <<< 16 < 2^32 := by rw [Nat.shiftLeft_eq]; omega
  have hc8 : c.toNat <<< 8 < 2^32 := by rw [Nat.shiftLeft_eq]; omega
  simp only [show (24 : UInt32).toNat = 24 from rfl,
    show (16 : UInt32).toNat = 16 from rfl, show (8 : UInt32).toNat = 8 from rfl,
    show 24 % 32 = 24 from rfl, show 16 % 32 = 16 from rfl, show 8 % 32 = 8 from rfl,
    Nat.mod_eq_of_lt (by omega : a.toNat < 2^32), Nat.mod_eq_of_lt (by omega : b.toNat < 2^32),
    Nat.mod_eq_of_lt (by omega : c.toNat < 2^32), Nat.mod_eq_of_lt (by omega : d.toNat < 2^32),
    Nat.mod_eq_of_lt ha24, Nat.mod_eq_of_lt hb16, Nat.mod_eq_of_lt hc8]
  have hp : a.toNat <<< 24 ||| b.toNat <<< 16 ||| c.toNat <<< 8 ||| d.toNat =
      ((a.toNat <<< 8 ||| b.toNat) <<< 8 ||| c.toNat) <<< 8 ||| d.toNat := by
    simp only [Nat.shiftLeft_or_distrib, ← Nat.shiftLeft_add]
  rw [hp, ← Nat.shiftLeft_add_eq_or_of_lt hb,
    ← Nat.shiftLeft_add_eq_or_of_lt hc, ← Nat.shiftLeft_add_eq_or_of_lt hd]
  simp only [Nat.shiftLeft_eq]
  omega

theorem signatureByte_get (sig : C10Signature) (i : Fin SignatureLen) :
    (toSpecSignatureBytes sig).get i = UInt8.ofNat (sig.val[i.val]!).val := by
  have hi : i.val < sig.val.length := by rw [sig.property]; exact i.isLt
  simp only [ByteVec.get, toSpecSignatureBytes]
  rw [getElem!_pos sig.val i.val hi]
  change (sig.val.map (fun x : Std.U8 => UInt8.ofNat x.val))[i.val]'(by simpa only [List.length_map] using hi) = _
  simp only [List.getElem_map]

theorem loadU32BE_parsed_count (sig : C10Signature) (layer : Fin 2) :
    ByteVec.loadU32BE (toSpecSignatureBytes sig) (3024+836*layer.val) =
      UInt32.ofNat (parsedLayerCount sig layer).val := by
  have hl := layer.isLt
  have h0 : 3024+836*layer.val < SignatureLen := by change 3024+836*layer.val < 4008; omega
  have h1 : 3024+836*layer.val+1 < SignatureLen := by change 3024+836*layer.val+1 < 4008; omega
  have h2 : 3024+836*layer.val+2 < SignatureLen := by change 3024+836*layer.val+2 < 4008; omega
  have h3 : 3024+836*layer.val+3 < SignatureLen := by change 3024+836*layer.val+3 < 4008; omega
  apply UInt32.toNat_inj.mp
  simp only [ByteVec.loadU32BE, dif_pos h0, dif_pos h1, dif_pos h2, dif_pos h3,
    signatureByte_get]
  rw [uint32_be_val]
  simp only [UInt8.toNat_ofNat', UInt32.toNat_ofNat']
  rw [Nat.mod_eq_of_lt (show (parsedLayerCount sig layer).val < 2^32 from (parsedLayerCount sig layer).hBounds), parsedLayerCount_val]
  simp only [Nat.mod_eq_of_lt (show (sig.val[3024+836*layer.val]!).val < 2^8 from (sig.val[3024+836*layer.val]!).hBounds),
    Nat.mod_eq_of_lt (show (sig.val[3024+836*layer.val+1]!).val < 2^8 from (sig.val[3024+836*layer.val+1]!).hBounds),
    Nat.mod_eq_of_lt (show (sig.val[3024+836*layer.val+2]!).val < 2^8 from (sig.val[3024+836*layer.val+2]!).hBounds),
    Nat.mod_eq_of_lt (show (sig.val[3024+836*layer.val+3]!).val < 2^8 from (sig.val[3024+836*layer.val+3]!).hBounds)]

attribute [local irreducible] ByteVec.loadU32BE parsedLayerCount ByteVec.loadValue16 toSpecNode

theorem deserialise_layers (sig : C10Signature) :
    (Signature.deserialise (toSpecSignatureBytes sig)).layers =
      (parsedSignature sig).layers := by
  have hp : parsedHypertreeLayers sig = _root_.Array.ofFn (fun l : Fin 2 => toSpecLayer sig l) := by
    simp [parsedHypertreeLayers, _root_.Array.ofFn_succ]
  simp only [Signature.deserialise, parsedSignature]
  rw [hp]
  apply congrArg _root_.Array.ofFn
  funext layer
  simp only [toSpecLayer, toSpecSigma, parsedLayerChains, parsedLayerAuth,
    List.map_ofFn, List.toArray_ofFn]
  have layerExt (a b : Hypertree.LayerSig) (hw : a.wots = b.wots)
      (ha : a.authPath = b.authPath) : a = b := by
    cases a; cases b; cases hw; cases ha; rfl
  have sigmaExt (a b : Wots.Sigma) (hc : a.chains = b.chains)
      (hn : a.count = b.count) : a = b := by
    cases a; cases b; cases hc; cases hn; rfl
  apply layerExt
  · apply sigmaExt
    · apply congrArg _root_.Array.ofFn
      funext i
      change ByteVec.loadValue16 (toSpecSignatureBytes sig) (2336+layer.val*836+i.val*16) =
        toSpecNode (layerChainBytes sig layer i)
      simpa only [layerChainBytes, Nat.mul_comm] using
        loadValue16_signatureNode sig ⟨2336+836*layer.val+16*i.val, by
          have hl : layer.val < 2 := by simpa only [D] using layer.isLt
          have hi : i.val < 43 := by simpa only [L] using i.isLt
          omega⟩
    · change ByteVec.loadU32BE (toSpecSignatureBytes sig) (2336+layer.val*836+688) = _
      rw [show 2336+layer.val*836+688 = 3024+836*layer.val by omega]
      exact loadU32BE_parsed_count sig layer
  · apply congrArg _root_.Array.ofFn
    funext h
    change ByteVec.loadValue16 (toSpecSignatureBytes sig) (2336+layer.val*836+688+4+h.val*16) =
      toSpecNode (layerAuthBytes sig layer h)
    rw [show 2336+layer.val*836+688+4+h.val*16 = 3028+836*layer.val+16*h.val by omega]
    simpa only [layerAuthBytes, Nat.mul_comm] using
      loadValue16_signatureNode sig ⟨3028+836*layer.val+16*h.val, by
        have hl : layer.val < 2 := by simpa only [D] using layer.isLt
        have hh : h.val < 9 := by simpa only [SubtreeH] using h.isLt
        omega⟩

/-- Every field of the complete faithful decoder is the corresponding actual
    parser value. No default or out-of-range branch supplies signature bytes. -/
theorem deserialise_matches_parsedSignature (sig : C10Signature) :
    Signature.deserialise (toSpecSignatureBytes sig) = parsedSignature sig := by
  have ext (a b : Hypertree.Signature) (hr : a.r = b.r)
      (hf : a.fors = b.fors) (hl : a.layers = b.layers) : a = b := by
    cases a; cases b; cases hr; cases hf; cases hl; rfl
  exact ext _ _ (deserialise_randomizer sig) (deserialise_fors sig) (deserialise_layers sig)

end Extracted.Equiv
