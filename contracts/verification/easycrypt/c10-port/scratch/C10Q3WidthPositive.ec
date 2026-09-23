require import AllCore List C10RawOracle RawKeygen PathInputs.
lemma width_counterexample prefix :
  prefix ++ pad [] ++ pad (nseq 16 0) = prefix ++ pad (nseq 16 0) ++ pad [] /\
  ([],nseq 16 0) <> (nseq 16 0,[]).
proof. exact (padded_pair_without_width_alias prefix). qed.
