import C10Probability.Memo
import Mathlib.Data.List.OfFn

/-! Serialized WOTS counter schedules. The counter occupies the final four
bytes of a full 32-byte big-endian block. Uniqueness within this call does not
imply absence from an earlier shared history. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

abbrev Counter := Fin (2 ^ 32)
abbrev ByteKey := List (Fin 256)

def counterDigest (c : Counter) : Digest :=
  ⟨c.val, lt_trans c.isLt (by norm_num)⟩

def counterBytes (c : Counter) : DigestBytes := bytesDigestEquiv.symm (counterDigest c)

theorem counter_byte_value (c : Counter) (i : Fin 32) :
    (counterBytes c i).val = c.val / 256 ^ (31 - i.val) % 256 :=
  digest_byte_value (counterDigest c) i

theorem counter_leading_zero (c : Counter) (i : Fin 32) (hi : i.val < 28) :
    counterBytes c i = 0 := by
  apply Fin.ext
  rw [counter_byte_value]
  have hp : 2 ^ 32 ≤ 256 ^ (31 - i.val) := by
    calc
      2 ^ 32 = 256 ^ 4 := by norm_num
      _ ≤ 256 ^ (31 - i.val) := Nat.pow_le_pow_right (by decide) (by omega)
  rw [Nat.div_eq_of_lt (lt_of_lt_of_le c.isLt hp)]
  rfl

theorem counter_last_byte (c : Counter) : (counterBytes c 31).val = c.val % 256 := by
  rw [counter_byte_value]; simp

theorem counter_bytes_injective : Function.Injective counterBytes := by
  intro a b h
  have hd := bytesDigestEquiv.symm.injective h
  exact Fin.ext (congrArg (fun d : Digest => d.val) hd)

def counterKey (stem : ByteKey) (c : Counter) : ByteKey :=
  stem ++ List.ofFn (counterBytes c)

theorem counter_key_length (stem : ByteKey) (c : Counter) :
    (counterKey stem c).length = stem.length + 32 := by simp [counterKey]

theorem counter_key_injective (stem : ByteKey) : Function.Injective (counterKey stem) := by
  intro a b h
  apply counter_bytes_injective
  exact List.ofFn_injective (List.append_cancel_left h)

def counterSchedule (stem : ByteKey) (start n : ℕ) (hb : start + n ≤ 2 ^ 32) :
    List ByteKey :=
  List.ofFn fun i : Fin n => counterKey stem ⟨start + i.val, by omega⟩

theorem counter_schedule_length (stem : ByteKey) (start n : ℕ)
    (hb : start + n ≤ 2 ^ 32) : (counterSchedule stem start n hb).length = n := by
  simp [counterSchedule]

theorem counter_schedule_nodup (stem : ByteKey) (start n : ℕ)
    (hb : start + n ≤ 2 ^ 32) : (counterSchedule stem start n hb).Nodup := by
  rw [List.nodup_iff_pairwise_ne, counterSchedule, List.pairwise_ofFn]
  intro i j hij he
  have hv := congrArg Fin.val (counter_key_injective stem he)
  have : i.val < j.val := hij
  simp only at hv
  omega

theorem signing_counter_fits : 0 + signingBudget ≤ 2 ^ 32 := by decide

theorem counter_grind_fresh (p : PMF Digest) (accept : Digest → Bool)
    (table : Memo ByteKey Digest) (stem : ByteKey) (start n : ℕ)
    (hb : start + n ≤ 2 ^ 32)
    (hf : ∀ key ∈ counterSchedule stem start n hb, table key = none) :
    (memoGrind p accept table start (counterSchedule stem start n hb)).map Prod.fst =
      grind p accept start n := by
  rw [memoGrind_fresh p accept table start _ (counter_schedule_nodup stem start n hb) hf,
    counter_schedule_length]

theorem wots_memo_projection (table : Memo ByteKey Digest) (stem : ByteKey)
    (hf : ∀ key ∈ counterSchedule stem 0 signingBudget signing_counter_fits,
      table key = none) :
    ((memoGrind digestDraw (wotsAccept ∘ wotsOfDigest) table 0
      (counterSchedule stem 0 signingBudget signing_counter_fits)).map Prod.fst).map
        (projectResult wotsOfDigest) = grind wotsDraw wotsAccept 0 signingBudget := by
  rw [counter_grind_fresh _ _ _ _ _ _ _ hf, wots_digest_search_projection]

theorem wots_memo_exhaustion (table : Memo ByteKey Digest) (stem : ByteKey)
    (hf : ∀ key ∈ counterSchedule stem 0 signingBudget signing_counter_fits,
      table key = none) :
    (((memoGrind digestDraw (wotsAccept ∘ wotsOfDigest) table 0
      (counterSchedule stem 0 signingBudget signing_counter_fits)).map Prod.fst) none).toReal =
      (1 - (Nat.card AcceptedWots : ℝ) / (8 : ℝ) ^ 43) ^ signingBudget := by
  rw [counter_grind_fresh _ _ _ _ _ _ _ hf, wots_digest_exhaustion_real]

end
end C10Probability
