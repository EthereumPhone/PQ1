import C10Probability.Transfer
import C10Probability.Counter

/-! Independent randomizer keys and cached H_msg replies. The high128bit
projection and padded byte input are explicit. The missing full-session step
is identifying actual secret-keyed R queries with these independent draws. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

abbrev Randomizer := Fin (2 ^ 128)
abbrev RandomizerBytes := Fin 16 → Fin 256

def digestHalves : Digest ≃ Randomizer × Randomizer :=
  (finCongr (by norm_num)).trans finProdFinEquiv.symm

def randomizerOfDigest (d : Digest) : Randomizer := (digestHalves d).1

theorem randomizer_value (d : Digest) :
    (randomizerOfDigest d).val = d.val / 2 ^ 128 := by rfl

def randomizerDraw : PMF Randomizer := digestDraw.map randomizerOfDigest

theorem randomizer_uniform : randomizerDraw = PMF.uniformOfFintype Randomizer := by
  have h := congrArg (PMF.map (Prod.fst : Randomizer × Randomizer → Randomizer))
    (uniform_map_equiv digestHalves)
  rw [uniform_map_fst] at h
  simpa only [PMF.map_comp, Function.comp_def, randomizerDraw, randomizerOfDigest,
    digestDraw] using h

def reverseRandomizerBytes : RandomizerBytes ≃ RandomizerBytes where
  toFun bytes i := bytes i.rev
  invFun bytes i := bytes i.rev
  left_inv bytes := by funext i; simp
  right_inv bytes := by funext i; simp

def randomizerBytesEquiv : RandomizerBytes ≃ Randomizer :=
  reverseRandomizerBytes.trans (finFunctionFinEquiv.trans (finCongr (by norm_num)))

theorem randomizer_byte_value (r : Randomizer) (i : Fin 16) :
    (randomizerBytesEquiv.symm r i).val = r.val / 256 ^ (15 - i.val) % 256 := by
  change r.val / 256 ^ i.rev.val % 256 = _
  simp only [Fin.val_rev]
  congr 3; omega

/-- Truncation means the first16 big-endian digest bytes, not its low128bits. -/
theorem randomizer_digest_byte (d : Digest) (i : Fin 16) :
    randomizerBytesEquiv.symm (randomizerOfDigest d) i =
      bytesDigestEquiv.symm d ⟨i.val, by omega⟩ := by
  apply Fin.ext
  rw [randomizer_byte_value, randomizer_value, digest_byte_value,
    Nat.div_div_eq_div_mul]
  simp only
  congr 3
  rw [show (2 : ℕ) ^ 128 = 256 ^ 16 by norm_num, ← pow_add]
  congr 1; omega

theorem randomizer_low_bit_dropped : (randomizerOfDigest 1).val = 0 := by decide

theorem randomizer_first_retained_bit :
    (randomizerOfDigest ⟨2 ^ 128, by decide⟩).val = 1 := by decide

theorem randomizer_first_byte :
    (randomizerBytesEquiv.symm ⟨2 ^ 120, by decide⟩ 0).val = 1 := by decide

theorem randomizer_last_byte : (randomizerBytesEquiv.symm 1 15).val = 1 := by decide

/-- `seed || root || R[16] || zero[16] || message || FF[32]`. -/
def hmsgRandomizerInput (seed root message : ByteKey) (r : Randomizer) : ByteKey :=
  (seed ++ root) ++ List.ofFn (randomizerBytesEquiv.symm r) ++ List.replicate 16 0 ++
    (message ++ List.replicate 32 255)

theorem hmsg_randomizer_length (seed root message : ByteKey) (r : Randomizer)
    (hs : seed.length = 32) (hr : root.length = 32) (hm : message.length = 32) :
    (hmsgRandomizerInput seed root message r).length = 160 := by
  simp [hmsgRandomizerInput, hs, hr, hm]

theorem hmsg_randomizer_injective (seed root message : ByteKey) :
    Function.Injective (hmsgRandomizerInput seed root message) := by
  intro a b h
  apply randomizerBytesEquiv.symm.injective
  exact List.ofFn_injective
    (List.append_cancel_left (List.append_cancel_right (List.append_cancel_right h)))

theorem hmsg_randomizer_zero_layout :
    hmsgRandomizerInput [] [] [] 0 = List.replicate 32 0 ++ List.replicate 32 255 := by
  decide

def randomizerMemoSearch (table : Memo ByteKey Digest) (seed root message : ByteKey)
    (n : ℕ) : PMF (Option (ℕ × Digest) × Memo ByteKey Digest) :=
  randomMemoGrind (randomizerDraw.map (hmsgRandomizerInput seed root message)) digestDraw
    (forsAccept ∘ forsOfDigest) table 0 n

/- Every starting cache is covered by its finite preimage under the injective
randomizer encoding. The error is derived for the online memoized experiment. -/
theorem randomizer_search_error_real (table : Memo ByteKey Digest)
    (seed root message : ByteKey) (n : ℕ) (event : Set (Option (ℕ × Digest))) :
    |(((randomizerMemoSearch table seed root message n).map Prod.fst).toOuterMeasure event).toReal -
      ((grind digestDraw (forsAccept ∘ forsOfDigest) 0 n).toOuterMeasure event).toReal| ≤
      (collisionPairs (embeddedHistory table (hmsgRandomizerInput seed root message)).card n : ℝ) /
        (2 : ℝ) ^ 128 := by
  simpa only [randomizerMemoSearch, randomizer_uniform, Fintype.card_fin, Nat.cast_pow,
    Nat.cast_ofNat] using
    randomMemo_event_error_real digestDraw (forsAccept ∘ forsOfDigest) table
      (hmsgRandomizerInput seed root message) (hmsg_randomizer_injective seed root message)
      (embeddedHistory table (hmsgRandomizerInput seed root message))
      (embeddedHistory_covers table (hmsgRandomizerInput seed root message)) 0 n event

theorem fors_memo_exhaustion_error (table : Memo ByteKey Digest)
    (seed root message : ByteKey) (n : ℕ) :
    |(((randomizerMemoSearch table seed root message n).map Prod.fst) none).toReal -
      (1 - (1 : ℝ) / 2048) ^ n| ≤
      (collisionPairs (embeddedHistory table (hmsgRandomizerInput seed root message)).card n : ℝ) /
        (2 : ℝ) ^ 128 := by
  have h := randomizer_search_error_real table seed root message n {none}
  simpa only [PMF.toOuterMeasure_apply_singleton, grind_none_real, digest_fors_acceptance,
    ENNReal.toReal_inv, ENNReal.toReal_ofNat, one_div] using h

/-- Empty-history bound for every trial count. It still uses
independent R draws; it is not a theorem about the secret-keyed R procedure. -/
theorem fors_empty_memo_exhaustion_bound (seed root message : ByteKey) (n : ℕ) :
    (((randomizerMemoSearch (fun _ => none) seed root message n).map Prod.fst)
      none).toReal ≤ (1 - (1 : ℝ) / 2048) ^ n +
        (n.choose 2 : ℝ) / (2 : ℝ) ^ 128 := by
  have h := fors_memo_exhaustion_error (fun _ => none) seed root message n
  simp only [embeddedHistory_empty, Finset.card_empty, collisionPairs, mul_zero, zero_add] at h
  have hu := (abs_le.mp h).2
  linarith


/-- Specialize after proving the symbolic bound; do not evaluate huge powers. -/
theorem fors_empty_memo_signing_exhaustion (seed root message : ByteKey) :
    (((randomizerMemoSearch (fun _ => none) seed root message signingBudget).map Prod.fst)
      none).toReal ≤ (1 - (1 : ℝ) / 2048) ^ signingBudget +
        (signingBudget.choose 2 : ℝ) / (2 : ℝ) ^ 128 := by
  exact fors_empty_memo_exhaustion_bound seed root message signingBudget

end
end C10Probability
