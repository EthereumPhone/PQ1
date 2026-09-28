(* Positive encoding counterexample: cardinality alone does not fix row widths. *)
require import AllCore List.
require import C10RawOracle RawKeygen ForestWitness.

lemma forest_compression_width_alias seed ht :
  let a = [] :: nseq 16 0 :: nseq 11 (nseq 16 0) in
  let b = nseq 16 0 :: [] :: nseq 11 (nseq 16 0) in
  size a=13 /\ size b=13 /\ a<>b /\
  forest_compress_input seed ht a=forest_compress_input seed ht b.
proof.
  rewrite /forest_compress_input /= /pad /= !flatten_cons !catA; smt(size_nseq).
qed.
