require import AllCore List C10Randomizer.
lemma wrong_half : truncate_r (nseq 128 false ++ nseq 128 true) = nseq 128 false.
proof. by rewrite /truncate_r drop_cat size_nseq /= drop0. qed.
