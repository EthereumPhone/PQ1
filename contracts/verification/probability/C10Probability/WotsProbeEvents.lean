import C10Probability.WotsGameOpening
import C10Probability.C10ProbePublic
import C10Probability.WotsOpeningTransfer

/-! The selected-cut event includes ordinary raw/verifier probe values and
the two forged signature coordinates. Truncation gives a bound on every
syntactic output; the proved actual query bound makes it exact on executions. -/
namespace C10Probability
noncomputable section

def wotsCutProgram (seed : ByteKey) (target : WotsCutTarget) :
    QueryProgram WotsQuery Digest Randomizer (target.2.val + 1) :=
  wotsSeedChainProgram id seed (wotsTargetLayer target.1) (wotsTargetTree target.1)
    (wotsTargetKp target.1) target.1.2.val target.2.val

def wotsForgedCoordinate (out : C10ProbedGame) (layer : ℕ) (chain : Fin 43) : Randomizer :=
  ((out.1.driver.session.session.value.2.layers[layer]?).getD emptyLayerSignature).sigma chain

def wotsProbeCandidates (limit : ℕ) (chain : Fin 43) (out : C10ProbedGame) : Finset Randomizer :=
  prefixCandidates nodeQueryDecode ((c10ProbeQueries out).take limit) ∪
    {wotsForgedCoordinate out 0 chain, wotsForgedCoordinate out 1 chain}

theorem wots_probe_candidates_card (limit : ℕ) (chain : Fin 43) (out : C10ProbedGame) :
    (wotsProbeCandidates limit chain out).card ≤ limit + 2 := by
  have prefixBound : (prefixCandidates nodeQueryDecode ((c10ProbeQueries out).take limit)).card ≤ limit :=
    (prefixCandidates_card_le _ _).trans (by simp only [List.length_take]; exact min_le_left _ _)
  have pairBound : ({wotsForgedCoordinate out 0 chain, wotsForgedCoordinate out 1 chain} :
      Finset Randomizer).card ≤ 2 := (Finset.card_insert_le _ _).trans (by simp)
  exact (Finset.card_union_le _ _).trans (Nat.add_le_add prefixBound pairBound)

theorem wots_forged_lower_candidate (limit : ℕ) (chain : Fin 43) (out : C10ProbedGame) :
    wotsForgedCoordinate out 0 chain ∈ wotsProbeCandidates limit chain out := by
  simp only [wotsProbeCandidates, Finset.mem_union, Finset.mem_insert, Finset.mem_singleton]
  exact Or.inr (Or.inl True.intro)

theorem wots_forged_upper_candidate (limit : ℕ) (chain : Fin 43) (out : C10ProbedGame) :
    wotsForgedCoordinate out 1 chain ∈ wotsProbeCandidates limit chain out := by
  simp only [wotsProbeCandidates, Finset.mem_union, Finset.mem_insert, Finset.mem_singleton]
  exact Or.inr (Or.inr True.intro)

theorem wots_probe_value_candidate (limit : ℕ) (chain : Fin 43) (out : C10ProbedGame)
    (length : (c10ProbeQueries out).length ≤ limit) (key : WotsQuery) (value : Randomizer)
    (member : key ∈ c10ProbeQueries out) (decoded : nodeQueryDecode key = some value) :
    value ∈ wotsProbeCandidates limit chain out := by
  apply Finset.mem_union_left
  apply (prefixCandidates_mem nodeQueryDecode _ value).mpr
  rw [List.take_of_length_le length]
  exact ⟨key, member, decoded⟩

def WotsProbeHit (seed : ByteKey) (target : WotsCutTarget) (out : C10ProbedGame)
    (table : Memo WotsQuery Digest) : Prop :=
  0 < target.2.val ∧ ∃ previous,
    replayProgram table (wotsBeforeCutProgram seed target.1 target.2.val) = some previous ∧
      wotsCutIncoming seed target previous ∈ c10ProbeQueries out

def wotsProbedReturned (target : WotsCutTarget) (cfg : C10SessionConfig)
    (out : C10ProbedGame) (table : Memo WotsQuery Digest) : Prop :=
  WotsReturned target (sessionConfigAt cfg out.1.key) out.1.driver.session.exposures table

def wotsProbedExcluded (seed : ByteKey) (target : WotsCutTarget) (cfg : C10SessionConfig)
    (out : C10ProbedGame) (table : Memo WotsQuery Digest) : Prop :=
  wotsProbedReturned target cfg out table ∨ WotsProbeHit seed target out table

def wotsProbedOpeningEvent (seed : ByteKey) (target : WotsCutTarget) (cfg : C10SessionConfig)
    (qr : ℕ) : Set (C10ProbedGame × Memo WotsQuery Digest) :=
  replayedOpeningEvent (wotsCutProgram seed target) (wotsProbeCandidates (qr + 361) target.1.2)
    (wotsProbedReturned target cfg)

def wotsProbedUnrevealedEvent (seed : ByteKey) (target : WotsCutTarget) (cfg : C10SessionConfig)
    (qr : ℕ) : Set (C10ProbedGame × Memo WotsQuery Digest) :=
  replayedOpeningEvent (wotsCutProgram seed target) (wotsProbeCandidates (qr + 361) target.1.2)
    (wotsProbedExcluded seed target cfg)

theorem wots_probe_hit_zero (seed : ByteKey) (target : WotsCutTarget) (out : C10ProbedGame)
    (table : Memo WotsQuery Digest) (zero : target.2.val = 0) : ¬ WotsProbeHit seed target out table := by
  intro hit
  have := hit.1
  omega

end
end C10Probability
