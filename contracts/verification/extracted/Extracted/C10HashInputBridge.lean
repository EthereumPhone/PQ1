/- Paired hash-preimage endpoints. Equalities concern the bytes before hashing;
   they do not assume hash injectivity or identify SHA with an ideal oracle.
   The shared expression generator and cross-tool interpretation remain TCB. -/
import Extracted.C10Representation
import Extracted.HashSpecs
import Extracted.GrindRSpec

open Aeneas Aeneas.Std Result
open sphincs_c10
namespace Extracted.C10HashInputBridge
open C10Representation
set_option maxRecDepth 8192

def byteInts (bs : List Std.U8) : List Int := bs.map (fun b => Int.ofNat b.val)
def bytesOfInts (bs : List Int) : List Std.U8 :=
  bs.map (fun b => ⟨BitVec.ofNat 8 b.toNat⟩)

theorem bytesOfInts_byteInts (bs : List Std.U8) : bytesOfInts (byteInts bs) = bs := by
  induction bs with
  | nil => rfl
  | cons b bs ih =>
    simp only [byteInts, bytesOfInts, List.map_cons] at *
    rw [ih]
    congr 1
    apply UScalar.eq_of_val_eq
    change b.val % 256 = b.val
    exact Nat.mod_eq_of_lt b.hBounds

theorem byteInts_append (a b : List Std.U8) :
    byteInts (a ++ b) = byteInts a ++ byteInts b := by simp [byteInts]

theorem u32_bytes_value (n : Nat) :
    byteInts (u32beBytes n) = u32_bytes (Int.ofNat n) := by
  have hu (x : Nat) : (⟨BitVec.ofNat 8 x⟩ : Std.U8).val = x % 256 := rfl
  simp [byteInts, u32beBytes, u32_bytes, List.range_succ, hu,
    Nat.shiftRight_eq_div_pow,
    Int.natCast_ediv, Int.natCast_emod]

theorem pad_node_value (v : Std.Array Std.U8 16#usize) :
    byteInts (pad16Pure v).val = pad_node (byteInts v.val) := by
  simp [byteInts, pad16Pure_val, pad_node]

theorem hmsg_input_value (seed root random message : Std.Array Std.U8 32#usize) :
    byteInts (seed.val ++ root.val ++ random.val ++ message.val ++ List.replicate 32 255#u8) =
      hmsg_preimage (byteInts seed.val) (byteInts root.val)
        (byteInts random.val) (byteInts message.val) := by
  simp [byteInts, hmsg_preimage]

theorem th_input_value (seed address value : Std.Array Std.U8 32#usize) :
    byteInts (seed.val ++ address.val ++ value.val) =
      th_preimage (byteInts seed.val) (byteInts address.val) (byteInts value.val) := by
  simp [byteInts, th_preimage]

theorem pair_input_value (seed address left right : Std.Array Std.U8 32#usize) :
    byteInts (seed.val ++ address.val ++ left.val ++ right.val) =
      pair_preimage (byteInts seed.val) (byteInts address.val)
        (byteInts left.val) (byteInts right.val) := by
  simp [byteInts, pair_preimage]

theorem padded_nodes_value (vs : List (Std.Array Std.U8 16#usize)) :
    byteInts ((vs.map (fun v => (pad16Pure v).val)).flatten) =
      ((vs.map (fun v => byteInts v.val)).foldr (fun v tail => pad_node v ++ tail) []) := by
  induction vs with
  | nil => rfl
  | cons v vs ih =>
    simp only [List.map_cons, List.flatten_cons, List.foldr_cons,
      byteInts_append, pad_node_value, ih]

theorem multi_input_value (seed address : Std.Array Std.U8 32#usize)
    (vs : Slice (Std.Array Std.U8 16#usize)) :
    byteInts (seed.val ++ address.val ++ (vs.val.map (fun v => (pad16Pure v).val)).flatten) =
      multi_preimage (byteInts seed.val) (byteInts address.val)
        (vs.val.map (fun v => byteInts v.val)) := by
  simp only [byteInts_append, padded_nodes_value, multi_preimage]

theorem wots_input_value (seed address message : Std.Array Std.U8 32#usize)
    (nonce : Std.U32) :
    byteInts (seed.val ++ address.val ++ message.val ++
      (List.replicate 28 0#u8 ++ u32beBytes nonce.val)) =
      wots_preimage (byteInts seed.val) (byteInts address.val)
        (byteInts message.val) (Int.ofNat nonce.val) := by
  simp only [byteInts_append, u32_bytes_value, wots_preimage]
  simp [byteInts, List.append_assoc]

def optionalBytes (r : Option (Std.Array Std.U8 16#usize)) : List Std.U8 :=
  r.elim [] (fun x => x.val)

theorem r_input_value (secret message : Std.Array Std.U8 32#usize)
    (random : Option (Std.Array Std.U8 16#usize)) (nonce : Std.U32) :
    byteInts (secret.val ++ [82#u8,95#u8,103#u8,114#u8,105#u8,110#u8,100#u8] ++
      (optionalBytes random) ++ message.val ++
      List.replicate 28 0#u8 ++ u32beBytes nonce.val) =
      r_preimage (byteInts secret.val)
        (byteInts (optionalBytes random))
        (byteInts message.val) (Int.ofNat nonce.val) := by
  cases random <;> simp only [byteInts_append, u32_bytes_value, r_preimage] <;>
    simp [byteInts, optionalBytes]

theorem extracted_hmsg_input (seed root random message : Std.Array Std.U8 32#usize) :
    hash.h_msg seed root random message = .ok (sha256_pure
      (bytesOfInts (hmsg_preimage (byteInts seed.val) (byteInts root.val)
        (byteInts random.val) (byteInts message.val)))) := by
  rw [← hmsg_input_value, bytesOfInts_byteInts, hash.h_msg_spec]

theorem extracted_th_input (seed address value : Std.Array Std.U8 32#usize) :
    hash.th seed address value ⦃ r => r = truncate16 (sha256_pure
      (bytesOfInts (th_preimage (byteInts seed.val) (byteInts address.val)
        (byteInts value.val)))) ⦄ := by
  rw [← th_input_value, bytesOfInts_byteInts]
  simpa only [th_pure_def] using hash.th_spec seed address value

theorem extracted_pair_input (seed address left right : Std.Array Std.U8 32#usize) :
    hash.th_pair seed address left right ⦃ r => r = truncate16 (sha256_pure
      (bytesOfInts (pair_preimage (byteInts seed.val) (byteInts address.val)
        (byteInts left.val) (byteInts right.val)))) ⦄ := by
  rw [← pair_input_value, bytesOfInts_byteInts]
  simpa only [th_pair_pure_def] using hash.th_pair_spec seed address left right

theorem extracted_multi_input (seed address : Std.Array Std.U8 32#usize)
    (vs : Slice (Std.Array Std.U8 16#usize)) (hn : vs.val.length ≤ 43) :
    hash.th_multi seed address vs ⦃ r => r = truncate16 (sha256_pure
      (bytesOfInts (multi_preimage (byteInts seed.val) (byteInts address.val)
        (vs.val.map (fun v => byteInts v.val))))) ⦄ := by
  rw [← multi_input_value, bytesOfInts_byteInts]
  simpa only [th_multi_pure_def] using hash.th_multi_spec seed address vs hn

theorem extracted_wots_input (seed address message : Std.Array Std.U8 32#usize)
    (nonce : Std.U32) :
    hash.wots_digest seed address message nonce ⦃ r => r = sha256_pure
      (bytesOfInts (wots_preimage (byteInts seed.val) (byteInts address.val)
        (byteInts message.val) (Int.ofNat nonce.val))) ⦄ := by
  rw [← wots_input_value, bytesOfInts_byteInts]
  simpa only [wots_digest_pure_def] using hash.wots_digest_spec seed address message nonce

/-- This is the randomizer expression consumed by the existing extracted
    grinder-body theorem, including both OptRand modes and every u32 nonce. -/
theorem randomizer_input (secret message : Std.Array Std.U8 32#usize)
    (random : Option (Std.Array Std.U8 16#usize)) (nonce : Std.U32) :
    Equiv.forsRandomizer secret message random nonce = truncate16 (sha256_pure
      (bytesOfInts (r_preimage (byteInts secret.val)
        (byteInts (optionalBytes random))
        (byteInts message.val) (Int.ofNat nonce.val)))) := by
  rw [← r_input_value, bytesOfInts_byteInts]
  cases random <;> rfl

/-- The actual bounded grinder body consumes that same common preimage.
    Its acceptance test and continuation remain those of the extracted model. -/
theorem extracted_grind_input (secret seed root message : Std.Array Std.U8 32#usize)
    (random : Option (Std.Array Std.U8 16#usize)) (nonce : Std.U32)
    (hbound : nonce.val < 10000000) :
    fors.grind_r_loop.body secret message random seed root 132#usize nonce ⦃ r =>
      (r = ControlFlow.done (truncate16 (sha256_pure
          (bytesOfInts (r_preimage (byteInts secret.val) (byteInts (optionalBytes random))
            (byteInts message.val) (Int.ofNat nonce.val)))),
          Equiv.forsGrindDigest secret seed root message random nonce) ∧
        Equiv.forsGrindAccept secret seed root message random nonce) ∨
      (∃ next, r = ControlFlow.cont next ∧ next.val = nonce.val + 1 ∧
        ¬ Equiv.forsGrindAccept secret seed root message random nonce) ⦄ := by
  rw [← randomizer_input]
  exact Equiv.fors_grind_body_spec secret seed root message random nonce hbound

end Extracted.C10HashInputBridge
