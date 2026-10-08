(* Each complete thirteen-tree forest reference has one root in fixed tables. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawSignature RawForest.
require import ForestRootWitness ForsRootDeterminism.

lemma forest_root_unique h s seed ht root root' :
  forest_root_witness h s seed ht root => forest_root_witness h s seed ht root' => root=root'.
proof.
  move=> [roots lastroot special final [hw [hf [hl [he [hr [hc hv]]]]]]]
    [roots' lastroot' special' final' [hw' [hf' [hl' [he' [hr' [hc' hv']]]]]]].
  have hl_eq := fors_root_witness_unique h s seed ht 12 lastroot lastroot' hl hl'.
  have special_eq : special=special' by smt().
  have roots_eq : roots=roots'.
  + apply (eq_from_nth (nseq 16 0)); first by move: hw hw'; rewrite /rows_width; smt().
    move=> i hi; have hi' : 0<=i<13 by move: hw hi; rewrite /rows_width; smt().
    case (i<12) => hit.
    - have hit' : 0<=i<12 by smt().
      exact (fors_root_witness_unique h s seed ht i _ _ (hf i hit') (hf' i hit')).
    have -> : i=12 by smt().
    smt().
  smt().
qed.
