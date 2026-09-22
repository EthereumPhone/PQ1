require import AllCore List IntDiv C10HypertreeCoverage.
lemma one_path_covers_cell :
  (forall layer, 0 <= layer < 2 =>
    !(layer = 0 /\ (path_cell 0 layer).`1 = 1 /\ (path_cell 0 layer).`2 = 0)) =>
  !(0 = 0 /\ 1 = 1 /\ 0 = 0).
proof. by rewrite /path_cell subtree_width /=. qed.
