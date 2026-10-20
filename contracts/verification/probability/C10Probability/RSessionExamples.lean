import C10Probability.RSessionBranches
import C10Probability.RSessionNumeric

/-! Direct-interpreter witnesses for admission, refusal, caps, failure and
repeated success. Populated-table examples establish operational behavior;
they are not assertions that these tables occur in an initialized experiment. -/
namespace C10Probability
noncomputable section

def rExampleContext : RContext := ([], List.replicate 32 0)
def rExampleConfig : RSessionConfig :=
  ⟨List.replicate 32 1, List.replicate 32 2, 1, by decide⟩
def rExampleZeroConfig : RSessionConfig :=
  { rExampleConfig with trials := 0, bound := by decide }
def rExampleSuccess : RSearchResult := (0, randomizerOfDigest (2 ^ 128), 2 ^ 128)

theorem r_session_admission_vectors :
    rSessionAdmits emptyRGrindLedger rExampleContext = true ∧
    rSessionAdmits emptyRGrindLedger (List.replicate 16 7, List.replicate 32 0) = true ∧
    rSessionAdmits emptyRGrindLedger (List.replicate 15 7, List.replicate 32 0) = false ∧
    rSessionAdmits emptyRGrindLedger ([], List.replicate 31 0) = false ∧
    rSessionAdmits emptyRGrindLedger ([], List.replicate 33 0) = false ∧
    rSessionAdmits ⟨[], true⟩ rExampleContext = false := by decide +kernel

theorem r_session_hash_after_failure (table : Memo (Sum ByteKey ByteKey) Digest)
    (cached : table (.inl [7]) = some 42) :
    rSession id rExampleConfig (.hash [7] (fun reply => .done reply) : RGrindClient Digest 1)
      1 4 ⟨[rExampleContext], true⟩ table =
        PMF.pure (⟨42, ⟨[rExampleContext], true⟩, 0, 4⟩, table) := by
  simp only [rSession, id_eq, memoQuery_cached digestDraw table (.inl [7]) 42 cached, PMF.pure_bind]

theorem r_session_hash_cap_default (table : Memo (Sum ByteKey ByteKey) Digest) :
    rSession id rExampleConfig (.hash [7] (fun reply => .done reply) : RGrindClient Digest 1)
      0 4 emptyRGrindLedger table = PMF.pure (⟨0, emptyRGrindLedger, 0, 4⟩, table) := by
  exact rfl

theorem r_session_grind_cap_default (table : Memo (Sum ByteKey ByteKey) Digest) :
    rSession id rExampleConfig
      (.grind rExampleContext (fun reply => .done reply.isNone) : RGrindClient Bool 1)
      3 0 emptyRGrindLedger table = PMF.pure (⟨true, emptyRGrindLedger, 3, 0⟩, table) := by
  exact rfl

theorem r_session_bad_context_keeps_cap (table : Memo (Sum ByteKey ByteKey) Digest) :
    rSession id rExampleConfig
      (.grind ([], []) (fun reply => .done reply.isNone) : RGrindClient Bool 1)
      3 2 emptyRGrindLedger table = PMF.pure (⟨true, emptyRGrindLedger, 3, 2⟩, table) := by
  have refused : rSessionAdmits emptyRGrindLedger ([], []) = false := by decide +kernel
  rw [r_session_grind_refused _ _ _ _ _ _ _ _ refused]
  rfl

theorem r_session_zero_trials_absorb (table : Memo (Sum ByteKey ByteKey) Digest) :
    rSession id rExampleZeroConfig
      (.grind rExampleContext (fun first => .grind rExampleContext
        (fun second => .done (first.isNone, second.isNone))) : RGrindClient (Bool × Bool) 2)
      3 2 emptyRGrindLedger table = PMF.pure (⟨(true, true), ⟨[], true⟩, 3, 1⟩, table) := by
  have admitted : rSessionAdmits emptyRGrindLedger rExampleContext = true := by decide +kernel
  rw [r_session_grind_exhausted _ _ _ _ 3 1 _ table table admitted
    (randomizer_under_zero _ _ _ _ _ _ _)]
  rw [r_session_grind_refused _ _ _ _ _ _ _ _ (r_session_failed_refuses _ _ rfl)]
  rfl

theorem r_example_cached_search :
    randomizerUnder id (fun _ => some (2 ^ 128)) rExampleContext.1 rExampleContext.2
      rExampleConfig.seed rExampleConfig.root rExampleConfig.trials rExampleConfig.bound =
      PMF.pure (some rExampleSuccess, fun _ => some (2 ^ 128)) := by
  have accepted : forsAccept (forsOfDigest (2 ^ 128)) = true := by decide +kernel
  simp [rExampleConfig, randomizerUnder, counterSchedule, derivedMemoGrind,
    memoQuery, PMF.pure_bind, accepted, rExampleSuccess]

theorem r_session_two_cached_searches :
    rSession id rExampleConfig
      (.grind rExampleContext (fun first => .grind rExampleContext
        (fun second => .done (first, second))) :
          RGrindClient (Option RSearchResult × Option RSearchResult) 2)
      3 2 emptyRGrindLedger (fun _ => some (2 ^ 128)) =
        PMF.pure (⟨(some rExampleSuccess, some rExampleSuccess),
          ⟨[rExampleContext, rExampleContext], false⟩, 3, 0⟩, fun _ => some (2 ^ 128)) := by
  have first : rSessionAdmits emptyRGrindLedger rExampleContext = true := by decide +kernel
  have second : rSessionAdmits ⟨[rExampleContext], false⟩ rExampleContext = true := by decide +kernel
  rw [r_session_grind_returned _ _ _ _ 3 1 _ _ _ rExampleSuccess first r_example_cached_search]
  simp only [emptyRGrindLedger, List.nil_append]
  rw [r_session_grind_returned _ _ _ _ 3 0 _ _ _ rExampleSuccess second r_example_cached_search]
  rfl

theorem r_session_public_between_replays :
    rSession id rExampleConfig
      (.grind rExampleContext (fun first => .hash [7] (fun raw => .grind rExampleContext
        (fun second => .done (first, raw, second)))) :
          RGrindClient (Option RSearchResult × Digest × Option RSearchResult) 3)
      1 2 emptyRGrindLedger (fun _ => some (2 ^ 128)) =
        PMF.pure (⟨(some rExampleSuccess, 2 ^ 128, some rExampleSuccess),
          ⟨[rExampleContext, rExampleContext], false⟩, 0, 0⟩, fun _ => some (2 ^ 128)) := by
  have first : rSessionAdmits emptyRGrindLedger rExampleContext = true := by decide +kernel
  have second : rSessionAdmits ⟨[rExampleContext], false⟩ rExampleContext = true := by decide +kernel
  rw [r_session_grind_returned _ _ _ _ 1 1 _ _ _ rExampleSuccess first r_example_cached_search]
  rw [r_session_hash_live]
  simp only [emptyRGrindLedger, List.nil_append, memoQuery, PMF.pure_bind]
  rw [r_session_grind_returned _ _ _ _ 0 0 _ _ _ rExampleSuccess second r_example_cached_search]
  rfl

theorem r_session_zero_grind_cap_exhaustion (cfg : RSessionConfig)
    {R : Type*} {fuel : ℕ} (clients : PMF (RGrindClient R fuel)) (qr : ℕ) :
    ((rIndependentSession cfg clients qr 0).map rSessionFailure) true = 0 := by
  apply le_antisymm _ (zero_le _)
  simpa only [Nat.cast_zero, zero_mul] using
    r_independent_session_exhaustion cfg clients qr 0

end
end C10Probability
