require import AllCore List BoundedAssignmentWords.
lemma canonical_two_count : canonical_assignment_count 2=2048.
proof. by rewrite /canonical_assignment_count /canonical_bounds /bounded_word_count /mkseq /range /=
    (iotaS 0 11 _) 1:/# /= (iotaS 1 10 _) 1:/# /= (iotaS 2 9 _) 1:/# /= (iotaS 3 8 _) 1:/# /= (iotaS 4 7 _) 1:/# /= (iotaS 5 6 _) 1:/# /= (iotaS 6 5 _) 1:/# /= (iotaS 7 4 _) 1:/# /= (iotaS 8 3 _) 1:/# /= (iotaS 9 2 _) 1:/# /= (iotaS 10 1 _) 1:/# /= (iotaS 11 0 _) 1:/# /= iota0 // /min /max /=. qed.
