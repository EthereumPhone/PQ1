import C10Probability.SecretPrefix

/-! First grinding call after an adaptive public-query prelude. Parameters may
depend on the public prelude's returned value, but not on the independent
secret. The comparison retains that value and the selected counter/digest.
It does not model an earlier signing interface or secret-dependent keygen. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

structure GrindRequest where
  random : ByteKey
  message : ByteKey
  seed : ByteKey
  root : ByteKey

def RequestValid (request : GrindRequest) : Prop :=
  (request.random.length = 0 ∨ request.random.length = 16) ∧
    request.message.length = 32 ∧ request.seed.length = 32 ∧ request.root.length = 32

variable {R : Type*}

def preludeShared {q : ℕ} (client : PMF (QueryProgram ByteKey Digest R q))
    (request : R → GrindRequest) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) :
    PMF (R × Option (ℕ × Digest)) :=
  (secretPrelude digestDraw digestDraw client (fun _ => none)).bind fun prior =>
    (sharedRandomizerSearch prior.2.cache (secretBytes prior.1)
      (request prior.2.value).random (request prior.2.value).message
      (request prior.2.value).seed (request prior.2.value).root n hb).map
        fun out => (prior.2.value, forgetLabel out.1)

def preludeIndependent {q : ℕ} (client : PMF (QueryProgram ByteKey Digest R q))
    (request : R → GrindRequest) (n : ℕ) : PMF (R × Option (ℕ × Digest)) :=
  (randomizedTrace digestDraw client (fun _ => none)).bind fun prior =>
    (randomizerMemoSearch prior.cache (request prior.value).seed
      (request prior.value).root (request prior.value).message n).map
        fun out => (prior.value, out.1)

theorem preludeIndependent_with_secret {q : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R q)) (request : R → GrindRequest) (n : ℕ) :
    preludeIndependent client request n =
      (secretPrelude digestDraw digestDraw client (fun _ => none)).bind fun prior =>
        (randomizerMemoSearch prior.2.cache (request prior.2.value).seed
          (request prior.2.value).root (request prior.2.value).message n).map
            fun out => (prior.2.value, out.1) := by
  simp only [secretPrelude, PMF.bind_bind, PMF.bind_map, Function.comp_def, PMF.bind_const, preludeIndependent]

theorem prelude_grind_good {q : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R q)) (request : R → GrindRequest)
    (hv : ∀ value, RequestValid (request value)) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32)
    (prior : Digest × TraceOutput ByteKey Digest R)
    (hp : prior ∈ (secretPrelude digestDraw digestDraw client (fun _ => none)).support)
    (hg : prefixHit decodeSecretPrefix prior = false) :
    (sharedRandomizerSearch prior.2.cache (secretBytes prior.1)
      (request prior.2.value).random (request prior.2.value).message
      (request prior.2.value).seed (request prior.2.value).root n hb).map
        (fun out => (prior.2.value, forgetLabel out.1)) =
      (randomizerMemoSearch prior.2.cache (request prior.2.value).seed
        (request prior.2.value).root (request prior.2.value).message n).map
          (fun out => (prior.2.value, out.1)) := by
  have hvalid := hv prior.2.value
  have h := sharedRandomizer_result prior.2.cache (secretBytes prior.1)
    (request prior.2.value).random (request prior.2.value).message
    (request prior.2.value).seed (request prior.2.value).root n hb
    (secret_bytes_length prior.1) hvalid.2.1 hvalid.1 hvalid.2.2.1 hvalid.2.2.2
    (public_prelude_r_fresh client prior hp hg _ _ 0 n hb)
  have hm := congrArg (PMF.map (fun result => (prior.2.value, result))) h
  simpa only [PMF.map_comp, Function.comp_def] using hm

theorem prelude_event_bounds {q : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R q)) (request : R → GrindRequest)
    (hv : ∀ value, RequestValid (request value)) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32)
    (event : Set (R × Option (ℕ × Digest))) :
    (preludeShared client request n hb).toOuterMeasure event ≤
      (preludeIndependent client request n).toOuterMeasure event +
        (q : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 256 ∧
    (preludeIndependent client request n).toOuterMeasure event ≤
      (preludeShared client request n hb).toOuterMeasure event +
        (q : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 256 := by
  have h := mixture_event_bounds
    (secretPrelude digestDraw digestDraw client (fun _ => none))
    (fun prior => (sharedRandomizerSearch prior.2.cache (secretBytes prior.1)
      (request prior.2.value).random (request prior.2.value).message
      (request prior.2.value).seed (request prior.2.value).root n hb).map
        (fun out => (prior.2.value, forgetLabel out.1)))
    (fun prior => (randomizerMemoSearch prior.2.cache (request prior.2.value).seed
      (request prior.2.value).root (request prior.2.value).message n).map
        (fun out => (prior.2.value, out.1)))
    (prefixHit decodeSecretPrefix) (prelude_grind_good client request hv n hb) event
  have charge : ((secretPrelude digestDraw digestDraw client (fun _ => none)).map
      (prefixHit decodeSecretPrefix)) true ≤ (q : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 256 := by
    simpa only [digestDraw, Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat] using
      secretPrelude_prefix_bound decodeSecretPrefix digestDraw client (fun _ => none)
  rw [← preludeIndependent_with_secret] at h
  exact ⟨h.1.trans (add_le_add le_rfl charge), h.2.trans (add_le_add le_rfl charge)⟩

theorem prelude_event_error_real {q : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R q)) (request : R → GrindRequest)
    (hv : ∀ value, RequestValid (request value)) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32)
    (event : Set (R × Option (ℕ × Digest))) :
    |((preludeShared client request n hb).toOuterMeasure event).toReal -
      ((preludeIndependent client request n).toOuterMeasure event).toReal| ≤
        (q : ℝ) / (2 : ℝ) ^ 256 := by
  obtain ⟨hl, hr⟩ := prelude_event_bounds client request hv n hb event
  have hd : (q : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 256 ≠ ⊤ :=
    ENNReal.div_ne_top (by simp) (by simp)
  have hrealL := ENNReal.toReal_mono
    (ENNReal.add_ne_top.mpr ⟨event_mass_ne_top _ _, hd⟩) hl
  have hrealR := ENNReal.toReal_mono
    (ENNReal.add_ne_top.mpr ⟨event_mass_ne_top _ _, hd⟩) hr
  rw [ENNReal.toReal_add (event_mass_ne_top _ _) hd] at hrealL hrealR
  simp only [ENNReal.toReal_div, ENNReal.toReal_natCast, ENNReal.toReal_pow,
    ENNReal.toReal_ofNat] at hrealL hrealR
  exact abs_sub_le_iff.mpr ⟨by linarith, by linarith⟩

end
end C10Probability
