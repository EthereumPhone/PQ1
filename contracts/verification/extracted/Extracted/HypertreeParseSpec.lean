/- Exact byte parsing for the two actual WOTS/XMSS verifier layers. -/
import Extracted.ForsVerifierPrefix
open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10
set_option maxHeartbeats 4000000
set_option maxRecDepth 8192

abbrev WotsChains := Std.Array (Std.Array Std.U8 16#usize) 43#usize
abbrev XmssAuth := Std.Array (Std.Array Std.U8 16#usize) 9#usize

def layerChainBytes (sig : C10Signature) (layer : Fin 2) (i : Fin 43) : Std.Array Std.U8 16#usize :=
  signatureNode sig ⟨2336 + 836*layer.val + 16*i.val, by have := layer.isLt; have := i.isLt; omega⟩

def layerAuthBytes (sig : C10Signature) (layer : Fin 2) (i : Fin 9) : Std.Array Std.U8 16#usize :=
  signatureNode sig ⟨3028 + 836*layer.val + 16*i.val, by have := layer.isLt; have := i.isLt; omega⟩

theorem firmware_parse_layer_wots (sig : C10Signature) (layer : Fin 2)
    (offset : Std.Usize) (initial : WotsChains) (hoffset : offset.val = 2336 + 836*layer.val) :
    hypertree.verify_loop3_loop0 {start := 0#usize, «end» := 43#usize} sig offset initial
      ⦃ r => r.1.val = 3024 + 836*layer.val ∧ ∀ t : Fin 43,
        r.2.val[t.val]! = layerChainBytes sig layer t ⦄ := by
  have hLayer := layer.isLt
  unfold hypertree.verify_loop3_loop0
  apply loop.spec_decr_nat
    (measure := fun s : core.ops.range.Range Std.Usize × Std.Usize × WotsChains =>
      43 - s.1.start.val)
    (inv := fun s : core.ops.range.Range Std.Usize × Std.Usize × WotsChains =>
      s.1.«end».val = 43 ∧ s.1.start.val ≤ 43 ∧ s.2.1.val = 2336 + 836*layer.val + 16*s.1.start.val ∧
      ∀ t : Fin 43, t.val < s.1.start.val → s.2.2.val[t.val]! = layerChainBytes sig layer t)
  · rintro ⟨it, offset, secrets⟩ ⟨hend, hle, hoff, hinv⟩
    simp only at hend hle hoff hinv
    unfold hypertree.verify_loop3_loop0.body
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨t, it', heq, ht, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      exact ⟨by omega, fun t => hinv t (by have := t.isLt; omega)⟩
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have htv : t.val = it.start.val := by rw [ht]
      have ht43 : t.val < 43 := by omega
      simp only [params.N]
      step* <;> first | scalar_tac | skip
      refine ⟨by rw [hend']; exact hend, by omega, by omega, ?_, by omega⟩
      intro q hq
      rw [a_post2, Array.set_val_eq]
      have hslen : secrets.val.length = 43 := by simpa using secrets.property
      by_cases hqt : q.val = t.val
      · rw [List.set_getElem!_eq _ _ _ _ ⟨by omega, hqt.symm⟩]
        apply Subtype.ext
        rw [s_post2, s2_post, Array.from_slice_val a s1 (by
          simpa only [Slice.length, i1_post, Nat.add_sub_cancel_left] using s1_post2)]
        simp only [s1_post1, Array.val_to_slice, layerChainBytes, signatureNode]
        congr 1 <;> omega
      · rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega)]
        exact hinv q (by omega)
  · refine ⟨rfl, by simp, by simpa using hoffset, ?_⟩
    intro t h
    simp at h

theorem firmware_parse_layer_xmss (sig : C10Signature) (layer : Fin 2)
    (offset : Std.Usize) (initial : XmssAuth) (hoffset : offset.val = 3028 + 836*layer.val) :
    hypertree.verify_loop3_loop1 {start := 0#usize, «end» := 9#usize} sig offset initial
      ⦃ r => r.1.val = 3172 + 836*layer.val ∧ ∀ t : Fin 9,
        r.2.val[t.val]! = layerAuthBytes sig layer t ⦄ := by
  have hLayer := layer.isLt
  unfold hypertree.verify_loop3_loop1
  apply loop.spec_decr_nat
    (measure := fun s : core.ops.range.Range Std.Usize × Std.Usize × XmssAuth =>
      9 - s.1.start.val)
    (inv := fun s : core.ops.range.Range Std.Usize × Std.Usize × XmssAuth =>
      s.1.«end».val = 9 ∧ s.1.start.val ≤ 9 ∧ s.2.1.val = 3028 + 836*layer.val + 16*s.1.start.val ∧
      ∀ t : Fin 9, t.val < s.1.start.val → s.2.2.val[t.val]! = layerAuthBytes sig layer t)
  · rintro ⟨it, offset, secrets⟩ ⟨hend, hle, hoff, hinv⟩
    simp only at hend hle hoff hinv
    unfold hypertree.verify_loop3_loop1.body
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨t, it', heq, ht, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      exact ⟨by omega, fun t => hinv t (by have := t.isLt; omega)⟩
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have htv : t.val = it.start.val := by rw [ht]
      have ht9 : t.val < 9 := by omega
      simp only [params.N]
      step* <;> first | scalar_tac | skip
      refine ⟨by rw [hend']; exact hend, by omega, by omega, ?_, by omega⟩
      intro q hq
      rw [a_post2, Array.set_val_eq]
      have hslen : secrets.val.length = 9 := by simpa using secrets.property
      by_cases hqt : q.val = t.val
      · rw [List.set_getElem!_eq _ _ _ _ ⟨by omega, hqt.symm⟩]
        apply Subtype.ext
        rw [s_post2, s2_post, Array.from_slice_val a s1 (by
          simpa only [Slice.length, i_post, Nat.add_sub_cancel_left] using s1_post2)]
        simp only [s1_post1, Array.val_to_slice, layerAuthBytes, signatureNode]
        congr 1 <;> omega
      · rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega)]
        exact hinv q (by omega)
  · refine ⟨rfl, by simp, by simpa using hoffset, ?_⟩
    intro t h
    simp at h

def parsedLayerChains (sig : C10Signature) (layer : Fin 2) : WotsChains :=
  ⟨List.ofFn (layerChainBytes sig layer), by simp⟩
def parsedLayerAuth (sig : C10Signature) (layer : Fin 2) : XmssAuth :=
  ⟨List.ofFn (layerAuthBytes sig layer), by simp⟩

theorem parsedLayerChains_get (sig : C10Signature) (layer : Fin 2) (j : Fin 43) :
    (parsedLayerChains sig layer).val[j.val]! = layerChainBytes sig layer j := by
  simp only [parsedLayerChains, List.getElem!_ofFn _ _ j.isLt]
theorem parsedLayerAuth_get (sig : C10Signature) (layer : Fin 2) (j : Fin 9) :
    (parsedLayerAuth sig layer).val[j.val]! = layerAuthBytes sig layer j := by
  simp only [parsedLayerAuth, List.getElem!_ofFn _ _ j.isLt]

theorem firmware_parse_layer_wots_value (sig : C10Signature) (layer : Fin 2)
    (offset : Std.Usize) (initial : WotsChains) (hoffset : offset.val = 2336 + 836*layer.val) :
    hypertree.verify_loop3_loop0 {start := 0#usize, «end» := 43#usize} sig offset initial
      ⦃ r => r.1.val = 3024 + 836*layer.val ∧ r.2 = parsedLayerChains sig layer ⦄ := by
  let* ⟨offset1, chains, ho, hc⟩ ← firmware_parse_layer_wots sig layer offset initial hoffset
  refine ⟨ho, ?_⟩
  apply fixedArray_ext
  intro q
  rw [hc q, parsedLayerChains_get]

theorem firmware_parse_layer_xmss_value (sig : C10Signature) (layer : Fin 2)
    (offset : Std.Usize) (initial : XmssAuth) (hoffset : offset.val = 3028 + 836*layer.val) :
    hypertree.verify_loop3_loop1 {start := 0#usize, «end» := 9#usize} sig offset initial
      ⦃ r => r.1.val = 3172 + 836*layer.val ∧ r.2 = parsedLayerAuth sig layer ⦄ := by
  let* ⟨offset1, auth, ho, ha⟩ ← firmware_parse_layer_xmss sig layer offset initial hoffset
  refine ⟨ho, ?_⟩
  apply fixedArray_ext
  intro q
  rw [ha q, parsedLayerAuth_get]

def layerCountBytes (sig : C10Signature) (layer : Fin 2) : Std.Array Std.U8 4#usize :=
  ⟨List.ofFn (fun j : Fin 4 => sig.val[3024 + 836*layer.val + j.val]!), by simp⟩

def parsedLayerCount (sig : C10Signature) (layer : Fin 2) : Std.U32 :=
  core.num.U32.from_be_bytes (layerCountBytes sig layer)

/-- The wire counter consumes all four bytes, including its most significant byte. -/
theorem from_four_be_val (a b c d : Std.U8) :
    (core.num.U32.from_be_bytes (Array.make 4#usize [a,b,c,d])).val =
      a.val*16777216 + b.val*65536 + c.val*256 + d.val := by
  have hb : (core.num.U32.from_be_bytes (Array.make 4#usize [a,b,c,d])).bv =
      ((a.bv ++ b.bv) ++ c.bv) ++ d.bv := by
    change BitVec.fromLEBytes [d.bv,c.bv,b.bv,a.bv] = _
    simp only [BitVec.fromLEBytes, List.length_cons, List.length_nil]
    simp only [BitVec.setWidth_zero, BitVec.zero_shiftLeft, BitVec.or_zero]
    rw [BitVec.or_comm (BitVec.setWidth 16 b.bv),
      ← BitVec.setWidth_append_eq_shiftLeft_setWidth_or]
    simp only [BitVec.setWidth_eq]
    rw [BitVec.or_comm (BitVec.setWidth 24 c.bv),
      ← BitVec.setWidth_append_eq_shiftLeft_setWidth_or]
    simp only [BitVec.setWidth_eq]
    rw [BitVec.or_comm (BitVec.setWidth 32 d.bv),
      ← BitVec.setWidth_append_eq_shiftLeft_setWidth_or]
    rfl
  change (core.num.U32.from_be_bytes (Array.make 4#usize [a,b,c,d])).bv.toNat = _
  rw [hb]
  simp only [BitVec.toNat_append]
  rw [← Nat.shiftLeft_add_eq_or_of_lt (show b.bv.toNat < 2^8 from b.hBounds),
      ← Nat.shiftLeft_add_eq_or_of_lt (show c.bv.toNat < 2^8 from c.hBounds),
      ← Nat.shiftLeft_add_eq_or_of_lt (show d.bv.toNat < 2^8 from d.hBounds)]
  simp only [Nat.shiftLeft_eq, show 2^8 = 256 from rfl]
  change ((a.val*256 + b.val)*256 + c.val)*256 + d.val = _
  omega


theorem parsedLayerCount_val (sig : C10Signature) (layer : Fin 2) :
    (parsedLayerCount sig layer).val =
      sig.val[3024+836*layer.val]!.val*16777216 +
      sig.val[3024+836*layer.val+1]!.val*65536 +
      sig.val[3024+836*layer.val+2]!.val*256 +
      sig.val[3024+836*layer.val+3]!.val := by
  have heq : layerCountBytes sig layer = Array.make 4#usize
      [sig.val[3024+836*layer.val]!, sig.val[3024+836*layer.val+1]!,
       sig.val[3024+836*layer.val+2]!, sig.val[3024+836*layer.val+3]!] := by
    rfl
  unfold parsedLayerCount
  rw [heq, from_four_be_val]

end Extracted.Equiv
