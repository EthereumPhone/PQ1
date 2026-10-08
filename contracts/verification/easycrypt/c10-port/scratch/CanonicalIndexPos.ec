require import AllCore List CanonicalWitnessIndices.
lemma final_assignment_index : index 7 (rev (undup [7;3;7]))<=0.
proof. exact (reverse_undup_index 0 [7;3;7] 2 _). qed.
