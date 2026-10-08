require import AllCore List C10RawOracle WotsDigitOrder.
lemma encoding_width (d : digest) : size (encoding_bits d)=129.
proof. by rewrite /encoding_bits size_mkseq. qed.
