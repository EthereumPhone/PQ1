import C10Probability.PrivateSecret

/-! Independent finite executions distinguish the real shared cache from the
ideal separate caches. These examples also exercise private replies influencing
later public inputs and the assumptions excluded by the interface theorem. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def privateThenPublic {K : Type*} (guess : K) : QueryProgram (Sum K Unit) Bool Bool 2 :=
  .query (.inr ()) (fun first => .query (.inl guess)
    (fun second => .done (decide (first = second))))

def publicThenPrivate {K : Type*} (guess : K) : QueryProgram (Sum K Unit) Bool Bool 2 :=
  .query (.inl guess) (fun first => .query (.inr ())
    (fun second => .done (decide (first = second))))

def privateRepeated : QueryProgram (Sum Bool Unit) Bool Bool 2 :=
  .query (.inr ()) (fun first => .query (.inr ())
    (fun second => .done (decide (first = second))))

def privateAdaptive : QueryProgram (Sum Bool Unit) Bool Bool 2 :=
  .query (.inr ()) (fun first => .query (.inl first)
    (fun second => .done (decide (first = second))))

theorem private_then_public_budget (guess : Bool) : PublicBudget (privateThenPublic guess) 1 := by
  simp [privateThenPublic, PublicBudget]

theorem public_then_private_budget (guess : Bool) : PublicBudget (publicThenPrivate guess) 1 := by
  simp [publicThenPrivate, PublicBudget]

theorem private_repeated_budget : PublicBudget privateRepeated 0 := by
  simp [privateRepeated, PublicBudget]

theorem private_adaptive_budget : PublicBudget privateAdaptive 1 := by
  simp [privateAdaptive, PublicBudget]

theorem private_then_public_shared_mass :
    privateShared fairReply fairReply (fun secret (_ : Unit) => secret)
      (PMF.pure (privateThenPublic false)) true = (3 : ℝ≥0∞) / 4 := by
  unfold privateShared
  rw [PMF.bind_apply, tsum_fintype, Fintype.sum_bool]
  simp [ privateSharedAt, privateThenPublic, privateKey, mapProgram,
    evalProgram, memoQuery, PMF.map_bind, PMF.bind_map, PMF.pure_map,
    Function.comp_def, PMF.bind_apply, fairReply, tsum_fintype]
  apply (ENNReal.toReal_eq_toReal_iff' (by finiteness) (by finiteness)).mp
  rw [ENNReal.toReal_add (by finiteness) (by finiteness)]
  norm_num [ENNReal.toReal_mul]

theorem public_then_private_shared_mass :
    privateShared fairReply fairReply (fun secret (_ : Unit) => secret)
      (PMF.pure (publicThenPrivate false)) true = (3 : ℝ≥0∞) / 4 := by
  unfold privateShared
  rw [PMF.bind_apply, tsum_fintype, Fintype.sum_bool]
  simp [ privateSharedAt, publicThenPrivate, privateKey, mapProgram,
    evalProgram, memoQuery, PMF.map_bind, PMF.bind_map, PMF.pure_map,
    Function.comp_def, PMF.bind_apply, fairReply, tsum_fintype]
  apply (ENNReal.toReal_eq_toReal_iff' (by finiteness) (by finiteness)).mp
  rw [ENNReal.toReal_add (by finiteness) (by finiteness)]
  norm_num [ENNReal.toReal_mul]

theorem private_then_public_ideal_mass {K : Type*} [DecidableEq K] (guess : K) :
    privateIndependent fairReply (PMF.pure (privateThenPublic guess)) true = (1 : ℝ≥0∞) / 2 := by
  simp [privateIndependent, randomizedProgram, privateThenPublic, evalProgram,
    memoQuery, PMF.map_bind, PMF.bind_map, PMF.pure_map,
    Function.comp_def, PMF.bind_apply, fairReply, tsum_fintype]
  rw [← mul_assoc, ENNReal.mul_inv_cancel (by norm_num) (by norm_num), one_mul]

theorem public_then_private_ideal_mass :
    privateIndependent fairReply (PMF.pure (publicThenPrivate false)) true = (1 : ℝ≥0∞) / 2 := by
  simp [privateIndependent, randomizedProgram, publicThenPrivate, evalProgram,
    memoQuery, PMF.map_bind, PMF.bind_map, PMF.pure_map,
    Function.comp_def, PMF.bind_apply, fairReply, tsum_fintype]
  rw [← mul_assoc, ENNReal.mul_inv_cancel (by norm_num) (by norm_num), one_mul]

theorem private_repeated_shared_mass :
    privateShared fairReply fairReply (fun secret (_ : Unit) => secret)
      (PMF.pure privateRepeated) true = 1 := by
  simp [privateShared, privateSharedAt, privateRepeated, privateKey, mapProgram,
    evalProgram, memoQuery, PMF.map_bind, PMF.bind_map, PMF.pure_map,
    Function.comp_def, fairReply]

theorem private_repeated_ideal_mass :
    privateIndependent fairReply (PMF.pure privateRepeated) true = 1 := by
  simp [privateIndependent, randomizedProgram, privateRepeated, evalProgram,
    memoQuery, PMF.map_bind, PMF.bind_map, PMF.pure_map,
    Function.comp_def, fairReply]

theorem private_adaptive_guess_mass :
    (fairReply.bind (privateGuess fairReply some (PMF.pure privateAdaptive))) true =
      (1 : ℝ≥0∞) / 2 := by
  simp [privateGuess, privateAdaptive, randomizedTrace, traceProgram, memoQuery,
    prefixHit, prefixCandidates, publicDecode, PMF.map_bind, PMF.bind_map,
    PMF.pure_map, Function.comp_def, PMF.bind_apply, fairReply, tsum_fintype]
  rw [← mul_assoc, ENNReal.mul_inv_cancel (by norm_num) (by norm_num), one_mul]

theorem private_short_public_not_bad (secret : Digest) :
    privateBad decodeSecretPrefix secret (.inl [] : Sum ByteKey ByteKey) = false := by
  simp [privateBad, publicDecode, decodeSecretPrefix_short [] (by decide)]

theorem private_public_event_gap :
    |(privateShared fairReply fairReply (fun secret (_ : Unit) => secret)
        (PMF.pure (privateThenPublic false)) true).toReal -
      (privateIndependent fairReply (PMF.pure (privateThenPublic false)) true).toReal| =
        (1 : ℝ) / 4 := by
  rw [private_then_public_shared_mass, private_then_public_ideal_mass]
  norm_num

theorem private_public_requires_public_budget : ¬ PublicBudget (privateThenPublic false) 0 := by
  simp [privateThenPublic, PublicBudget]

/-- These two experiments intentionally give the program the secret. They are
not instances of the secret-independent client argument in privateShared. -/
def leakedPrivateShared : PMF Bool :=
  (PMF.uniformOfFintype (Fin 3)).bind fun secret =>
    privateSharedAt fairReply (fun key (_ : Unit) => key) secret
      (PMF.pure (privateThenPublic secret))

def leakedPrivateIdeal : PMF Bool :=
  (PMF.uniformOfFintype (Fin 3)).bind fun secret =>
    privateIndependent fairReply (PMF.pure (privateThenPublic secret))

theorem leaked_private_shared_mass : leakedPrivateShared true = 1 := by
  simp [leakedPrivateShared, privateSharedAt, privateThenPublic, privateKey, mapProgram,
    evalProgram, memoQuery, PMF.map_bind, PMF.bind_map, PMF.pure_map,
    Function.comp_def, fairReply]

theorem leaked_private_ideal_mass : leakedPrivateIdeal true = (1 : ℝ≥0∞) / 2 := by
  rw [leakedPrivateIdeal, PMF.bind_apply]
  simp only [private_then_public_ideal_mass]
  rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

theorem leaked_private_breaks_prefix_charge :
    leakedPrivateIdeal true + (1 : ℝ≥0∞) / 3 < leakedPrivateShared true := by
  rw [leaked_private_shared_mass, leaked_private_ideal_mass]
  apply (ENNReal.toReal_lt_toReal (by finiteness) (by simp)).mp
  norm_num [ENNReal.toReal_add]

def privateDistinct : QueryProgram (Sum Bool Bool) Bool Bool 2 :=
  .query (.inr false) (fun first => .query (.inr true)
    (fun second => .done (decide (first = second))))

theorem noninjective_private_boundary :
    PublicBudget privateDistinct 0 ∧
    privateShared fairReply fairReply (fun secret (_ : Bool) => secret)
      (PMF.pure privateDistinct) true = 1 ∧
    privateIndependent fairReply (PMF.pure privateDistinct) true = (1 : ℝ≥0∞) / 2 := by
  refine ⟨by simp [privateDistinct, PublicBudget], ?_, ?_⟩
  · simp [privateShared, privateSharedAt, privateDistinct, privateKey, mapProgram,
      evalProgram, memoQuery, PMF.map_bind, PMF.bind_map, PMF.pure_map,
      Function.comp_def, fairReply]
  · simp [privateIndependent, randomizedProgram, privateDistinct, evalProgram,
      memoQuery, PMF.map_bind, PMF.bind_map, PMF.pure_map,
      Function.comp_def, PMF.bind_apply, fairReply, tsum_fintype]
    rw [← mul_assoc, ENNReal.mul_inv_cancel (by norm_num) (by norm_num), one_mul]

theorem prefilled_private_not_related :
    ¬ TablesRelate (privateKey (fun secret (_ : Unit) => secret) false)
      (privateBad some false) (fun _ => some false) (fun _ => none) := by
  intro h
  have bad : (some false : Option Bool) = none := h (.inr ()) rfl
  cases bad

end
end C10Probability
