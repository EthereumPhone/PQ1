require import AllCore List C10HashDomains.
lemma wrong_hmsg_length :
  size (hmsg_input (nseq 32 0) (nseq 32 0) (nseq 32 0) (nseq 32 0)) = 128.
proof. by rewrite hmsg_width 1..4:size_nseq. qed.
