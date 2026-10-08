require import AllCore List BoundedAssignmentWords.
lemma final_zero_is_canonical : canonical_assignment 2 (rcons (nseq 11 1) 0).
proof.
  rewrite canonical_assignment_shape; split.
  + by rewrite size_rcons size_nseq.
  move=> i hi; rewrite nth_rcons size_nseq /=.
  case (i=11)=> he; first smt().
  rewrite nth_nseq 1:/#; smt().
qed.
