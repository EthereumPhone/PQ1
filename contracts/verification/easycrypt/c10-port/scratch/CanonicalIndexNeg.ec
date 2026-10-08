require import AllCore List CanonicalWitnessIndices.
lemma final_assignment_index : index 7 (rev (undup [3;7;3;7]))=1.
proof. by rewrite /index /undup /=. qed.
