(* A complete, recorded catalog supplies the verifier-side path witness. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen NodeGridIndex NodeGridPath NodeCatalog NodeCatalogDomain PathReplay.

lemma catalog_complete_grid h f c total :
  0 <= total => catalog_exact c (2^total) => catalog_sound h f c =>
  grid_recorded h f (catalog_grid c) total.
proof.
  move=> ht hc hs; rewrite /grid_recorded.
  move=> level index hl hi.
  have hr := dyadic_index_range index 1 (total-level) _ hi; first by smt().
  move: hr; rewrite expr1; move=> hr.
  have hd : node_due (2^total) (level+1) (index %/ 2).
  + apply node_due_range; smt().
  have hm : (level+1,index %/ 2) \in c by apply hc.
  have hlink : catalog_link h f c (level+1) (index %/ 2) by have := hs _ _ hm; smt().
  move: hlink; rewrite /catalog_link /grid_link /catalog_grid /=.
  move=> [l0 r0 d hd']; exists d; smt(oget_some).
qed.

lemma catalog_recorded_path h f c total target :
  0 <= total => 0 <= target < 2^total =>
  catalog_exact c (2^total) => catalog_sound h f c =>
  path_recorded h f (catalog_grid c 0 target,0,target)
    (grid_auth (catalog_grid c) target total) /\
  (path_value h f (catalog_grid c 0 target,0,target)
    (grid_auth (catalog_grid c) target total)).`1 = catalog_grid c total 0.
proof.
  move=> hh ht hc hs.
  exact (grid_recorded_path h f (catalog_grid c) total target hh ht
    (catalog_complete_grid h f c total hh hc hs)).
qed.
