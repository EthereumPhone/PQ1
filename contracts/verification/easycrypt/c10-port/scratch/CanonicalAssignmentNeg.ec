require import AllCore List BoundedAssignmentWords.
lemma final_digit_invalid : !canonical_assignment 2 (nseq 12 1).
proof.
  rewrite canonical_assignment_shape.
  have hh : nth 0 (nseq 12 1) 11=1 by rewrite nth_nseq //.
  smt().
qed.
lemma final_digit : canonical_assignment 2 (nseq 12 1).
proof. by rewrite final_digit_invalid. qed.
