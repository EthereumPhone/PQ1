import C10Probability.QueryProgram

/-! Fresh sampling with adaptive stopping. The work index bounds every branch,
while the observed-length cap in the probability theorem may be smaller. The
client sees each reply but cannot inspect future samples. Client randomness is
a PMF over programs, sampled before their fresh replies. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

inductive SampleProgram (α R : Type*) : ℕ → Type _
  | done {n : ℕ} (value : R) : SampleProgram α R n
  | sample {n : ℕ} (next : α → SampleProgram α R n) : SampleProgram α R (n + 1)

def iidSampleList {α : Type*} (p : PMF α) : ℕ → PMF (List α)
  | 0 => PMF.pure []
  | n + 1 => p.bind fun value => (iidSampleList p n).map (List.cons value)

def evalSampleProgram {α R : Type*} (p : PMF α) :
    {n : ℕ} → SampleProgram α R n → PMF (R × List α)
  | _, .done value => PMF.pure (value, [])
  | _, .sample next => p.bind fun value =>
      (evalSampleProgram p (next value)).map fun out => (out.1, value :: out.2)

def randomizedSampleProgram {α R : Type*} (p : PMF α) {n : ℕ}
    (client : PMF (SampleProgram α R n)) : PMF (R × List α) :=
  client.bind (evalSampleProgram p)

def SampleExtensionClosed {α : Type*} (event : List α → Prop) : Prop :=
  ∀ before after, event before → event (before ++ after)

theorem iidSampleList_length {α : Type*} (p : PMF α) (n : ℕ)
    (xs : List α) (supported : xs ∈ (iidSampleList p n).support) : xs.length = n := by
  induction n generalizing xs with
  | zero => simpa [iidSampleList] using supported
  | succ n ih =>
    rw [iidSampleList, PMF.mem_support_bind_iff] at supported
    obtain ⟨value, _, supported⟩ := supported
    rw [PMF.mem_support_map_iff] at supported
    obtain ⟨tail, ht, rfl⟩ := supported
    simp [ih tail ht]

theorem evalSampleProgram_length {α R : Type*} (p : PMF α) {n : ℕ}
    (program : SampleProgram α R n) (out : R × List α)
    (supported : out ∈ (evalSampleProgram p program).support) : out.2.length ≤ n := by
  induction program generalizing out with
  | done value =>
    have he : out = (value, []) := by simpa [evalSampleProgram] using supported
    simp [he]
  | sample next ih =>
    rw [evalSampleProgram, PMF.mem_support_bind_iff] at supported
    obtain ⟨value, _, supported⟩ := supported
    rw [PMF.mem_support_map_iff] at supported
    obtain ⟨tail, ht, rfl⟩ := supported
    simpa using Nat.succ_le_succ (ih value tail ht)

theorem sample_extension_cons {α : Type*} {event : List α → Prop}
    (closed : SampleExtensionClosed event) (value : α) :
    SampleExtensionClosed (fun xs => event (value :: xs)) := by
  intro before after he
  exact closed (value :: before) after he

theorem iidSampleList_event_of_empty {α : Type*} (p : PMF α) (n : ℕ)
    (event : List α → Prop) (closed : SampleExtensionClosed event) (empty : event []) :
    (iidSampleList p n).toOuterMeasure {xs | event xs} = 1 := by
  apply (PMF.toOuterMeasure_apply_eq_one_iff _ _).2
  intro xs _
  exact closed [] xs empty

theorem evalSampleProgram_prefix_bound {α R : Type*} (p : PMF α) {n : ℕ}
    (program : SampleProgram α R n) (cap : ℕ) (event : List α → Prop)
    (closed : SampleExtensionClosed event) :
    (evalSampleProgram p program).toOuterMeasure
      {out | out.2.length ≤ cap ∧ event out.2} ≤
      (iidSampleList p cap).toOuterMeasure {xs | event xs} := by
  classical
  induction program generalizing cap event with
  | done value =>
    by_cases he : event []
    · rw [iidSampleList_event_of_empty p cap event closed he]
      simp [evalSampleProgram, he]
    · simp [evalSampleProgram, he]
  | sample next ih =>
    cases cap with
    | zero =>
      simp [evalSampleProgram, PMF.toOuterMeasure_bind_apply,
        PMF.toOuterMeasure_map_apply]
    | succ cap =>
      rw [evalSampleProgram, PMF.toOuterMeasure_bind_apply,
        iidSampleList, PMF.toOuterMeasure_bind_apply]
      apply ENNReal.tsum_le_tsum
      intro value
      rw [PMF.toOuterMeasure_map_apply, PMF.toOuterMeasure_map_apply]
      apply mul_le_mul_right
      simpa only [Set.preimage_setOf_eq, List.length_cons, Nat.succ_le_succ_iff] using
        ih value cap (fun xs => event (value :: xs)) (sample_extension_cons closed value)

theorem randomizedSampleProgram_prefix_bound {α R : Type*} (p : PMF α) {n : ℕ}
    (client : PMF (SampleProgram α R n)) (cap : ℕ) (event : List α → Prop)
    (closed : SampleExtensionClosed event) :
    (randomizedSampleProgram p client).toOuterMeasure
      {out | out.2.length ≤ cap ∧ event out.2} ≤
      (iidSampleList p cap).toOuterMeasure {xs | event xs} := by
  rw [randomizedSampleProgram, PMF.toOuterMeasure_bind_apply]
  calc
    _ ≤ ∑' program, client program *
        (iidSampleList p cap).toOuterMeasure {xs | event xs} := by
      apply ENNReal.tsum_le_tsum
      intro program
      exact mul_le_mul_right (evalSampleProgram_prefix_bound p program cap event closed) _
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

end
end C10Probability
