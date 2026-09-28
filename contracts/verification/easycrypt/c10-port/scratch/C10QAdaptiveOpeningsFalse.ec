require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Randomizer AcceptedCoverage C10QAdaptiveOpeningsPositive.

lemma false_future_sets_independent :
  mu full_digest (fun d => accept_digest d /\ prior_covered (matched_openings d) d) =
    (1%r/2%r)^143.
proof. exact adaptive_coverage_mass. qed.
