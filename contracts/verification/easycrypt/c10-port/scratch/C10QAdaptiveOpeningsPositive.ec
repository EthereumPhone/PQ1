(* A timing countermodel: sets chosen from the draw itself always cover it.
   Fixed-prior-set laws cannot be reused for arbitrary future enlarged sets. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Randomizer FORSC10Digest AcceptedCoverage.

op matched_openings (d : digest) =
  mkseq (fun i => [take 11 (drop (11*i) d)]) 12.

lemma matched_coverage d : prior_covered (matched_openings d) d.
proof.
  rewrite /prior_covered /matched_openings => i hi.
  by rewrite nth_mkseq 1:hi /=.
qed.

lemma adaptive_coverage_mass :
  mu full_digest (fun d => accept_digest d /\ prior_covered (matched_openings d) d) =
    (1%r/2%r)^11.
proof.
  rewrite (mu_eq _ _ accept_digest).
  + move=> d; have h := matched_coverage d; smt().
  exact fors_acceptance_mass.
qed.
