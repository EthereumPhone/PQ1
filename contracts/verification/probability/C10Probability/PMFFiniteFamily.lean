import Mathlib.Probability.ProbabilityMassFunction.Constructions
import Mathlib.Data.Fin.Tuple.Basic

/-! Finite families of independently sampled continuations. Each coordinate has
exactly the requested PMF, including when that PMF has infinite support. This
allows a finite cutoff to sample its possible continuations before the oracle
reply is known, without giving the client access to private oracle state. -/
namespace C10Probability
noncomputable section

def pmfTuple {B : Type*} : {n : ℕ} → (Fin n → PMF B) → PMF (Fin n → B)
  | 0, _ => PMF.pure Fin.elim0
  | n + 1, p => (p 0).bind fun head =>
      (pmfTuple (fun i : Fin n => p i.succ)).map (Fin.cons head)

theorem pmf_tuple_marginal {B : Type*} {n : ℕ} (p : Fin n → PMF B) (i : Fin n) :
    (pmfTuple p).map (fun values => values i) = p i := by
  induction n with
  | zero => exact Fin.elim0 i
  | succ n ih =>
    refine Fin.cases ?_ (fun j => ?_) i
    · simp only [pmfTuple, PMF.map_bind, PMF.map_comp, Function.comp_def, Fin.cons_zero]
      simp only [PMF.map, Function.comp_def, PMF.bind_const, PMF.bind_pure]
    · simp only [pmfTuple, PMF.map_bind, PMF.map_comp, Function.comp_def,
        Fin.cons_succ, ih, PMF.bind_const]

def pmfFamily {A B : Type*} [Fintype A] (p : A → PMF B) : PMF (A → B) :=
  (pmfTuple (fun i => p ((Fintype.equivFin A).symm i))).map
    (fun values a => values (Fintype.equivFin A a))

theorem pmf_family_marginal {A B : Type*} [Fintype A] (p : A → PMF B) (a : A) :
    (pmfFamily p).map (fun values => values a) = p a := by
  simp only [pmfFamily, PMF.map_comp, Function.comp_def, pmf_tuple_marginal,
    Equiv.symm_apply_apply]

theorem pmf_family_bind {A B C : Type*} [Fintype A] (p : A → PMF B) (a : A)
    (f : B → PMF C) :
    (pmfFamily p).bind (fun values => f (values a)) = (p a).bind f := by
  calc
    _ = ((pmfFamily p).map (fun values => values a)).bind f := (PMF.bind_map _ _ _).symm
    _ = _ := by rw [pmf_family_marginal]

end
end C10Probability
