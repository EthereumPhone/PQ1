/- Representation endpoint proofs for the extracted digest readers and actual
   signature-parser values. The paired EasyCrypt theory proves its endpoint
   against the generated forms. Their common expression tree/primitive
   interpretation is explicit TCB; no probability or full-session transfer. -/
import Extracted.C10Representation
import Extracted.ForsSpecBridge
import Extracted.WotsDigits
import Extracted.SignatureDecodeSpec
open Aeneas Aeneas.Std Result



namespace Extracted.C10RepresentationBridge
set_option maxRecDepth 8192
open C10Representation

open Extracted.Equiv

theorem reverse_digest_bytes (d : Std.Array Std.U8 32#usize) :
    (d.val.map (·.val)).reverse =
      (List.range 32).map (fun i => (d.val[31-i]!).val) := by
  have hlen : d.val.length = 32 := by simpa using d.property
  apply List.ext_getElem
  · simp [hlen]
  intro i h1 h2
  simp only [List.getElem_reverse, List.getElem_map, List.length_map, hlen,
    List.getElem_range]
  rw [getElem!_pos d.val (31-i) (by simp [hlen] at h1; omega)]

theorem byte_word_le_nat (bs : List Nat) :
    byte_word_le (bs.map Int.ofNat) = Int.ofNat (Nat.ofDigits 256 bs) := by
  induction bs with
  | nil => rfl
  | cons b bs ih =>
    simp only [byte_word_le, List.map_cons, List.foldr_cons] at *
    rw [ih, Nat.ofDigits_cons]
    rfl

theorem digest_byte_word (d : Std.Array Std.U8 32#usize) :
    byte_word (d.val.map (fun b => Int.ofNat b.val)) = Int.ofNat (digestWord d) := by
  unfold byte_word
  have hm : d.val.map (fun b => Int.ofNat b.val) =
      (d.val.map (·.val)).map Int.ofNat := by simp only [List.map_map]; rfl
  rw [hm, ← List.map_reverse, byte_word_le_nat, reverse_digest_bytes]
  rfl

theorem take_drop_ofFn {α : Type} [Inhabited α] (xs : List α) (off n : Nat)
    (h : off+n ≤ xs.length) :
    (xs.drop off).take n = List.ofFn (fun i : Fin n => xs[off+i.val]!) := by
  apply List.ext_getElem
  · simp only [List.length_take, List.length_drop, List.length_ofFn]
    omega
  intro i hi hj
  have hjn : i < n := by simpa only [List.length_ofFn] using hj
  rw [List.getElem_take, List.getElem_drop, List.getElem_ofFn,
    getElem!_pos xs (off+i) (by omega)]

def signatureBytes (sig : C10Signature) : List Int :=
  sig.val.map (fun b => Int.ofNat b.val)

theorem counter_word (sig : C10Signature) (layer : Fin 2) :
    byte_word (((signatureBytes sig).drop (3024+836*layer.val)).take 4) =
      Int.ofNat (parsedLayerCount sig layer).val := by
  have hl := layer.isLt
  have hs : sig.val.length = 4008 := by simpa using sig.property
  have hv : (((signatureBytes sig).drop (3024+836*layer.val)).take 4) =
      [Int.ofNat sig.val[3024+836*layer.val]!.val,
       Int.ofNat sig.val[3024+836*layer.val+1]!.val,
       Int.ofNat sig.val[3024+836*layer.val+2]!.val,
       Int.ofNat sig.val[3024+836*layer.val+3]!.val] := by
    unfold signatureBytes
    rw [← List.map_drop, ← List.map_take,
      take_drop_ofFn sig.val (3024+836*layer.val) 4 (by omega), List.map_ofFn]
    rfl
  rw [hv, parsedLayerCount_val]
  simp only [byte_word, byte_word_le, List.reverse_cons, List.reverse_nil,
    List.nil_append, List.cons_append, List.foldr_cons, List.foldr_nil,
    Int.ofNat_eq_natCast, Int.natCast_add, Int.natCast_mul]
  omega

abbrev WordLayer := List (List Int) × Int × List (List Int)
abbrev WordSignature := List Int × List (List Int) × List (List (List Int)) × List WordLayer

def nodeInts (node : Std.Array Std.U8 16#usize) : List Int :=
  node.val.map (fun b => Int.ofNat b.val)

def parsedLayerWords (sig : C10Signature) (l : Fin 2) : WordLayer :=
  ((parsedLayerChains sig l).val.map nodeInts, Int.ofNat (parsedLayerCount sig l).val,
   (parsedLayerAuth sig l).val.map nodeInts)

def parsedSignatureWords (sig : C10Signature) : WordSignature :=
  (nodeInts (verifierRandomizer sig), (parsedForsSecrets sig).val.map nodeInts,
   (parsedForsAuth sig).val.map (fun row => row.val.map nodeInts),
   List.ofFn (parsedLayerWords sig))

theorem range_map_ofFn {α : Type} (n : Nat) (f : Nat → α) :
    (List.range n).map f = List.ofFn (fun i : Fin n => f i.val) := by
  apply List.ext_getElem
  · simp only [List.length_map, List.length_range, List.length_ofFn]
  intro i hi hj
  simp only [List.getElem_map, List.getElem_range, List.getElem_ofFn]

theorem node_words (sig : C10Signature) (off : Fin 3993) :
    nodeInts (signatureNode sig off) = ((signatureBytes sig).drop off.val).take 16 := by
  simp only [nodeInts, signatureNode, signatureBytes, List.slice, Nat.add_sub_cancel_left,
    List.map_take, List.map_drop]

theorem layer_words (sig : C10Signature) (l : Fin 2) :
    word_layer (signatureBytes sig) (2336+836*l.val) = parsedLayerWords sig l := by
  unfold word_layer parsedLayerWords
  apply Prod.ext
  · simp only [word_nodes, range_map_ofFn, parsedLayerChains, List.map_ofFn]
    apply congrArg List.ofFn
    funext i
    simp only [Function.comp_apply, layerChainBytes]
    rw [node_words]
  · apply Prod.ext
    · rw [show 2336+836*l.val+688 = 3024+836*l.val by omega]
      exact counter_word sig l
    · simp only [word_nodes, range_map_ofFn, parsedLayerAuth, List.map_ofFn]
      apply congrArg List.ofFn
      funext i
      simp only [Function.comp_apply, layerAuthBytes]
      rw [node_words]
      congr 3
      omega

theorem signature_words (sig : C10Signature) :
    word_decode (signatureBytes sig) = parsedSignatureWords sig := by
  unfold word_decode parsedSignatureWords
  apply Prod.ext
  · simp only [nodeInts, verifierRandomizer, signatureBytes, List.slice,
      Nat.zero_add, Nat.sub_zero, List.drop_zero, List.map_take]
  · apply Prod.ext
    · simp only [word_nodes, range_map_ofFn, parsedForsSecrets, List.map_ofFn]
      apply congrArg List.ofFn
      funext t
      simp only [Function.comp_apply, forsSecretBytes]
      rw [node_words]
    · apply Prod.ext
      · simp only [range_map_ofFn, parsedForsAuth, List.map_ofFn]
        apply congrArg List.ofFn
        funext t
        simp only [Function.comp_apply, word_nodes, range_map_ofFn, List.map_ofFn]
        apply congrArg List.ofFn
        funext h
        simp only [Function.comp_apply, forsAuthBytes]
        rw [node_words]
      · change (List.range 2).map (fun l => word_layer (signatureBytes sig) (2336+836*l)) =
          List.ofFn (parsedLayerWords sig)
        rw [range_map_ofFn]
        apply congrArg List.ofFn
        funext l
        exact layer_words sig l
theorem digest_word_window (d : Std.Array Std.U8 32#usize) (off width : Nat) :
    word_window (d.val.map (fun b => Int.ofNat b.val)) off width =
      Int.ofNat ((digestWord d >>> off) % 2^width) := by
  unfold word_window
  rw [digest_byte_word]
  simp only [Int.ofNat_eq_natCast, Nat.shiftRight_eq_div_pow,
    Int.natCast_emod, Int.natCast_ediv, Int.natCast_pow, Int.cast_ofNat_Int]


attribute [local irreducible] digestWord

theorem extracted_ht_word (d : Std.Array Std.U8 32#usize) :
    sphincs_c10.fors.extract_ht_index d ⦃ r =>
      Int.ofNat r.val = ht_field (d.val.map (fun b => Int.ofNat b.val)) ⦄ := by
  unfold ht_field
  rw [digest_word_window]
  exact WP.spec_mono (extract_ht_index_spec d) (by intro r hr; exact congrArg Int.ofNat hr)

theorem extracted_fors_words (d : Std.Array Std.U8 32#usize) :
    sphincs_c10.fors.extract_fors_indices d ⦃ r =>
      ∀ j, j < 13 → Int.ofNat (r.val[j]!).val =
        fors_field (d.val.map (fun b => Int.ofNat b.val)) j ⦄ := by
  simp only [fors_field, digest_word_window]
  exact WP.spec_mono (extract_fors_indices_spec d) (by
    intro r hr j hj
    simpa only [Nat.mul_comm] using congrArg Int.ofNat (hr j hj))

theorem extracted_wots_words (d : Std.Array Std.U8 32#usize) :
    sphincs_c10.wots.extract_digits d ⦃ r =>
      ∀ j, j < 43 → Int.ofNat (r.val[j]!).val =
        wots_field (d.val.map (fun b => Int.ofNat b.val)) j ⦄ := by
  simp only [wots_field, digest_word_window, show (2:Nat)^3=8 by decide]
  exact WP.spec_mono (extract_digits_spec d) (by
    intro r hr j hj
    simpa only [Nat.mul_comm] using congrArg Int.ofNat (hr j hj))


/-- The EasyCrypt byte-domain premise is discharged by Rust's byte type. -/
theorem signature_byte_domain (sig : C10Signature) :
    (signatureBytes sig).length = 4008 ∧
    ∀ b ∈ signatureBytes sig, 0 ≤ b ∧ b < 256 := by
  constructor
  · simpa only [signatureBytes, List.length_map] using sig.property
  intro b hb
  obtain ⟨v, hv, rfl⟩ := List.mem_map.mp hb
  constructor
  · change (0 : Int) ≤ (v.val : Int)
    omega
  · change (v.val : Int) < (256 : Int)
    exact_mod_cast (show v.val < 256 from v.hBounds)

theorem digest_byte_domain (d : Std.Array Std.U8 32#usize) :
    (d.val.map (fun b => Int.ofNat b.val)).length = 32 ∧
    ∀ b ∈ d.val.map (fun b => Int.ofNat b.val), 0 ≤ b ∧ b < 256 := by
  constructor
  · simpa only [List.length_map] using d.property
  intro b hb
  obtain ⟨v, hv, rfl⟩ := List.mem_map.mp hb
  constructor
  · change (0 : Int) ≤ (v.val : Int)
    omega
  · change (v.val : Int) < (256 : Int)
    exact_mod_cast (show v.val < 256 from v.hBounds)

end Extracted.C10RepresentationBridge
