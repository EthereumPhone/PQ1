require import AllCore List Distr DList.
require import C10RawOracle AcceptedDigestDistribution CoverageAssignment SelectedCoverageMass.
lemma one_witness_charge :
  mu (dlist accepted_digest 2) (ordered_assignment_event 1 (nseq 12 0))=(1%r/2%r)^151.
proof.
  have hf : coverage_assignment 1 (nseq 12 0)
    by rewrite /coverage_assignment size_nseq all_nseq /is_digit; simplify.
  by rewrite (ordered_assignment_mass 1 (nseq 12 0) _ hf) //.
qed.
