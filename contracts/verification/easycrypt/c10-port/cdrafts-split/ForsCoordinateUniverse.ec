(* Finite ordinary FORS input universe; the special thirteenth tree is excluded. *)
require import AllCore List.
require import C10RawOracle RawForest ForsPrivateLeaves ForestCoordinates SignerCoordinates.

op ordinary_fors_coordinates =
  allpairs (fun (ht : int) (ti : int * int) => (ht,ti.`1,ti.`2)) (range 0 262144)
    (allpairs (fun tree index => (tree,index)) (range 0 12) (range 0 2048)).
lemma ordinary_fors_coordinate_member ht tree index :
  mem ordinary_fors_coordinates (ht,tree,index) <=>
    0<=ht<262144 /\ 0<=tree<12 /\ 0<=index<2048.
proof.
  rewrite /ordinary_fors_coordinates allpairsP.
  split.
  + move=> [p [hp [htp he]]]; move: htp; rewrite allpairsP;
      move=> [ti [htree [hi het]]]; move: hp htree hi; rewrite !mem_range; smt().
  move=> [hh [htree hi]]; exists (ht,(tree,index)); split; first by rewrite mem_range.
  split; last trivial.
  rewrite allpairsP; exists (tree,index); rewrite !mem_range; smt().
qed.
lemma ordinary_fors_universe_size : size ordinary_fors_coordinates=6442450944.
proof. rewrite /ordinary_fors_coordinates !size_allpairs !size_range; smt(). qed.
lemma ordinary_fors_output_coordinate d tree :
  0<=tree<12 => mem ordinary_fors_coordinates (hypertree_index d,tree,forest_index d tree).
proof. rewrite ordinary_fors_coordinate_member; smt(hypertree_index_range forest_index_range). qed.
