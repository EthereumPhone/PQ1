require import AllCore List RawSigner ChainByteCandidates.
lemma all_candidate_positions (signature : raw_signature) : size (wots_output_candidates signature)=12.
proof. by rewrite wots_output_candidates_size. qed.
