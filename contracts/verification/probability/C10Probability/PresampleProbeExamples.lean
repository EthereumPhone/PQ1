import C10Probability.ObservedWotsExposure
import C10Probability.OpeningExamples

/-! Cache restoration keeps the caller's baseline and actual query multiset.
Passive probes retain order, repetitions and full oracle replies. -/
namespace C10Probability
noncomputable section

theorem restored_unused_baseline_example :
    (restoreQueries (fun _ : Bool => some false)
      (⟨(), fun _ => some true, []⟩ : TraceOutput Bool Bool Unit)).cache false = some false := by
  simp [restoreQueries]

theorem restored_queried_duplicate_example :
    (restoreQueries (fun _ : Bool => some false)
      (⟨(), fun _ => some true, [false, false]⟩ : TraceOutput Bool Bool Unit)).cache false = some true ∧
    (restoreQueries (fun _ : Bool => some false)
      (⟨(), fun _ => some true, [false, false]⟩ : TraceOutput Bool Bool Unit)).queries = [false, false] := by
  simp [restoreQueries]

theorem restored_other_baseline_example :
    (restoreQueries (fun _ : Bool => some false)
      (⟨(), fun _ => some true, [true]⟩ : TraceOutput Bool Bool Unit)).cache false = some false := by
  simp [restoreQueries]

def adaptivePrecomputeExample : QueryProgram Bool Bool Bool 2 :=
  .query false (fun first => .query first (fun second => .done second))

def repeatedProbeExample : QueryProgram Bool Bool (Bool × Bool) 2 :=
  .query false (fun first => .query false (fun second => .done (first, second)))

theorem repeated_probe_cached_example (table : Memo Bool Bool) (cached : table false = some true) :
    evalProgram fairReply (probeProgram repeatedProbeExample) table =
      PMF.pure (((true, true), [false, false]), table) := by
  simp only [repeatedProbeExample, probeProgram, evalProgram, evalProgram_mapReturn,
    memoQuery_cached fairReply table false true cached, PMF.pure_bind, PMF.pure_map]

theorem adaptive_precompute_example (table : Memo Bool Bool) :
    traceProgram fairReply repeatedProbeExample table =
      (evalProgram fairReply adaptivePrecomputeExample table).bind (fun prepared =>
        (traceProgram fairReply repeatedProbeExample prepared.2).map (restoreQueries table)) := by
  exact trace_program_precompute fairReply adaptivePrecomputeExample repeatedProbeExample table

theorem probe_full_digest_example (secret : Digest) (table : Memo WotsQuery Digest)
    (key : WotsQuery) (cached : table key = some secret) :
    evalProgram digestDraw (probeProgram (.query key (fun value => .done (n := 0) value))) table =
      PMF.pure ((secret, [key]), table) := by
  simp only [probeProgram, evalProgram, evalProgram_mapReturn,
    memoQuery_cached digestDraw table key secret cached, PMF.pure_bind, PMF.pure_map]

theorem selected_probe_reveals_example (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (secret : Digest) (table : Memo WotsQuery Digest) :
    evalOpening digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
      (revealLift (wotsCutIncoming seed target previous)
        (probeProgram (.query (wotsCutIncoming seed target previous) (fun value => .done (n := 0) value))))
      table false = PMF.pure ⟨(secret, [wotsCutIncoming seed target previous]), table, true⟩ := by
  simp [probeProgram, revealLift, mapReturnProgram, evalOpening]

end
end C10Probability
