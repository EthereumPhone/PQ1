require import AllCore List BoundedAssignmentWords.
lemma final_digit_invalid : !canonical_assignment 2 (rcons (nseq 11 1) 1).
proof.
  apply/negP=> hc.
  move: hc; rewrite canonical_assignment_shape; move=> [hs h].
  have hh := h 11 _; first by [].
  by move: hh; rewrite nth_rcons size_nseq /=.
qed.
