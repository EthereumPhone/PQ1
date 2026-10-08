require import AllCore List BoundedAssignmentWords.
lemma final_digit_invalid : !canonical_assignment 2 (rcons (nseq 11 1) 0).
proof.
  rewrite canonical_assignment_shape.
  have hh : nth 0 (rcons (nseq 11 1) 0) 11=1 by rewrite nth_rcons size_nseq /=.
  smt().
qed.
