/- The common encoder retains every byte of the actual 4008-byte layout.
   This is a representation identity, independent of signer success or SHA. -/
import Extracted.C10RepresentationBridge
import Extracted.C10HashInputBridge
import Extracted.SignLayerSerialize
import Extracted.SignForestSerialize

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge Extracted.C10RepresentationBridge C10Representation
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000

namespace Extracted.C10FunctionalSignatureBytes

theorem nodes_bytes_flatten (rows : List (List Int)) : nodes_bytes rows = rows.flatten := by
  induction rows with
  | nil => rfl
  | cons row rows ih => simpa only [nodes_bytes, List.foldr_cons, List.flatten_cons] using congrArg (row ++ ·) ih

theorem chunks_join (bs : List Int) (width count off : Nat) :
    ((List.range count).map (fun j => (bs.drop (off+width*j)).take width)).flatten =
      (bs.drop off).take (width*count) := by
  induction count with
  | zero => simp
  | succ count ih =>
    rw [List.range_succ, List.map_append, List.flatten_append, List.map_singleton,
      List.flatten_singleton, ih, Nat.mul_succ, List.take_add, List.drop_drop]

theorem word_nodes_bytes (bs : List Int) (count off : Nat) :
    nodes_bytes (word_nodes count bs off) = (bs.drop off).take (16*count) := by
  rw [nodes_bytes_flatten, word_nodes, chunks_join]

theorem four_byte_encoding (a b c d : Int)
    (ha : 0 ≤ a ∧ a < 256) (hb : 0 ≤ b ∧ b < 256)
    (hc : 0 ≤ c ∧ c < 256) (hd : 0 ≤ d ∧ d < 256) :
    u32_bytes (a*16777216+b*65536+c*256+d) = [a,b,c,d] := by
  simp [u32_bytes, List.range_succ]
  omega

theorem parsed_counter_bytes (sig : Equiv.C10Signature) (layer : Fin 2) :
    u32_bytes (Int.ofNat (Equiv.parsedLayerCount sig layer).val) =
      ((signatureBytes sig).drop (3024+836*layer.val)).take 4 := by
  have hl := layer.isLt
  have hs : sig.val.length = 4008 := by simpa using sig.property
  have byte_bound (j : Nat) : 0 ≤ Int.ofNat sig.val[j]!.val ∧ Int.ofNat sig.val[j]!.val < 256 := by
    have hb : sig.val[j]!.val < 256 := sig.val[j]!.hBounds
    simp only [Int.ofNat_eq_natCast]
    constructor <;> omega
  rw [Equiv.parsedLayerCount_val]
  simp only [Int.ofNat_eq_natCast, Int.natCast_add, Int.natCast_mul, Nat.cast_ofNat]
  have he := four_byte_encoding _ _ _ _ (byte_bound (3024+836*layer.val))
    (byte_bound (3024+836*layer.val+1)) (byte_bound (3024+836*layer.val+2))
    (byte_bound (3024+836*layer.val+3))
  simp only [Int.ofNat_eq_natCast] at he
  rw [he]
  unfold signatureBytes
  rw [← List.map_drop, ← List.map_take,
    take_drop_ofFn sig.val (3024+836*layer.val) 4 (by omega), List.map_ofFn]
  rfl

def encodeWords (sig : WordSignature) : List Int :=
  let first := sig.2.2.2.getD 0 ([],0,[])
  let second := sig.2.2.2.getD 1 ([],0,[])
  signature_bytes sig.1 sig.2.1 sig.2.2.1
    first.1 first.2.1 first.2.2 second.1 second.2.1 second.2.2

theorem paths_bytes_flatten (paths : List (List (List Int))) :
    paths.foldr (fun row tail => nodes_bytes row ++ tail) [] =
      (paths.map nodes_bytes).flatten := by
  induction paths with
  | nil => rfl
  | cons row paths ih => simpa only [List.foldr_cons, List.map_cons, List.flatten_cons] using congrArg (nodes_bytes row ++ ·) ih

theorem chunk_cat (bs : List Int) (off n m : Nat) :
    (bs.drop off).take n ++ (bs.drop (off+n)).take m = (bs.drop off).take (n+m) := by
  rw [List.take_add, List.drop_drop]

theorem layer_encoding (sig : Equiv.C10Signature) (layer : Fin 2) :
    let fields := word_layer (signatureBytes sig) (2336+836*layer.val)
    layer_bytes fields.1 fields.2.1 fields.2.2 =
      ((signatureBytes sig).drop (2336+836*layer.val)).take 836 := by
  simp only [word_layer, layer_bytes, word_nodes_bytes]
  have hcount : 2336+836*layer.val+688 = 3024+836*layer.val := by omega
  rw [hcount, counter_word, parsed_counter_bytes]
  rw [show 16*43=688 from rfl, show 16*9=144 from rfl, ← hcount,
    chunk_cat, chunk_cat]

/-- The encoder is a left inverse of the actual parser on every input array,
    including arbitrary full-width counters and invalid cryptographic data. -/
theorem decoded_bytes (sig : Equiv.C10Signature) :
    encodeWords (word_decode (signatureBytes sig)) = signatureBytes sig := by
  have first := layer_encoding sig ⟨0, by decide⟩
  have second := layer_encoding sig ⟨1, by decide⟩
  simp only [Nat.mul_zero, Nat.add_zero] at first
  simp only [Nat.mul_one, Nat.reduceAdd] at second
  unfold encodeWords word_decode
  simp only [show List.range 2 = [0,1] from rfl, List.map_cons, List.map_nil,
    List.getD_cons_zero, List.getD_cons_succ, Nat.mul_zero, Nat.add_zero,
    Nat.mul_one, Nat.reduceAdd]
  simp only [signature_bytes, word_nodes_bytes, paths_bytes_flatten,
    List.map_map, Function.comp_def]
  change (signatureBytes sig).take 16 ++
      ((signatureBytes sig).drop 16).take 208 ++
      (((List.range 12).map (fun t =>
        ((signatureBytes sig).drop (224+176*t)).take 176)).flatten) ++
      layer_bytes (word_layer (signatureBytes sig) 2336).1
        (word_layer (signatureBytes sig) 2336).2.1 (word_layer (signatureBytes sig) 2336).2.2 ++
      layer_bytes (word_layer (signatureBytes sig) 3172).1
        (word_layer (signatureBytes sig) 3172).2.1 (word_layer (signatureBytes sig) 3172).2.2 = _
  rw [chunks_join, first, second]
  have h1 := chunk_cat (signatureBytes sig) 0 16 208
  simp only [List.drop_zero, Nat.zero_add] at h1
  rw [h1]
  have h2 := chunk_cat (signatureBytes sig) 0 224 2112
  simp only [List.drop_zero, Nat.zero_add] at h2
  rw [h2]
  have h3 := chunk_cat (signatureBytes sig) 0 2336 836
  simp only [List.drop_zero, Nat.zero_add] at h3
  rw [h3]
  have h4 := chunk_cat (signatureBytes sig) 0 3172 836
  simp only [List.drop_zero, Nat.zero_add] at h4
  rw [h4]
  apply List.take_of_length_le
  simp only [signatureBytes, List.length_map]
  simpa using Nat.le_of_eq sig.property

theorem parsed_bytes (sig : Equiv.C10Signature) :
    encodeWords (parsedSignatureWords sig) = signatureBytes sig := by
  rw [← signature_words, decoded_bytes]

end Extracted.C10FunctionalSignatureBytes
