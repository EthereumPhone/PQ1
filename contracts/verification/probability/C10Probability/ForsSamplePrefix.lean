import C10Probability.SamplePrefix
import C10Probability.ForsSelectedWitness

/-! The actual accepted FORS PMF supplies fresh replies. List-prefix sampling
and the previously proved fixed function-space pool have the same law. This
does not reinterpret cached H_msg replies as fresh accepted draws. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem iidSampleList_map {α β : Type*} (p : PMF α) (f : α → β) (n : ℕ) :
    iidSampleList (p.map f) n = (iidSampleList p n).map (List.map f) := by
  induction n with
  | zero => simp [iidSampleList, PMF.pure_map]
  | succ n ih =>
    simp only [iidSampleList, PMF.bind_map, PMF.map_bind, ih, PMF.map_comp,
      Function.comp_def, List.map_cons]

theorem uniform_samples_list (n : ℕ) (A : Type*) [Fintype A] [Nonempty A] :
    (PMF.uniformOfFintype (Fin n → A)).map List.ofFn =
      iidSampleList (PMF.uniformOfFintype A) n := by
  induction n with
  | zero =>
    rw [show (List.ofFn : (Fin 0 → A) → List A) = (fun _ => []) by
      funext samples
      simp]
    exact PMF.map_const _ _
  | succ n ih =>
    have h := congrArg (PMF.map (fun pair : A × (Fin n → A) =>
      pair.1 :: List.ofFn pair.2)) (uniform_samples_head_tail n A)
    simp only [PMF.map_comp, PMF.map_bind, Function.comp_def] at h
    rw [iidSampleList]
    calc
      _ = (PMF.uniformOfFintype A).bind fun head =>
          (PMF.uniformOfFintype (Fin n → A)).map
            (fun tail => head :: List.ofFn tail) := by
        rw [show (List.ofFn : (Fin (n + 1) → A) → List A) =
          (fun samples => samples 0 :: List.ofFn (fun i => samples i.succ)) by
            funext samples
            exact List.ofFn_succ]
        exact h
      _ = _ := by
        simp only [← ih, PMF.map_comp, Function.comp_def]

theorem accepted_fors_samples_list (n : ℕ) :
    (acceptedForsSamples n).map List.ofFn = iidSampleList acceptedForsDraw n := by
  rw [acceptedForsDraw, iidSampleList_map, ← uniform_samples_list,
    acceptedForsSamples, PMF.map_comp, PMF.map_comp]
  congr 1
  funext samples
  simp [Function.comp_def, List.map_ofFn]

theorem accepted_fors_program_prefix_bound {R : Type*} {work : ℕ}
    (client : PMF (SampleProgram Digest R work)) (cap : ℕ) (event : List Digest → Prop)
    (closed : SampleExtensionClosed event) :
    (randomizedSampleProgram acceptedForsDraw client).toOuterMeasure
      {out | out.2.length ≤ cap ∧ event out.2} ≤
      (acceptedForsSamples cap).toOuterMeasure {samples | event (List.ofFn samples)} := by
  have h := randomizedSampleProgram_prefix_bound acceptedForsDraw client cap event closed
  rw [← accepted_fors_samples_list, PMF.toOuterMeasure_map_apply] at h
  exact h

end
end C10Probability
