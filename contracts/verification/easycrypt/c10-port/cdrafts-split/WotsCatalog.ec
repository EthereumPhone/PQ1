(* Each actual Merkle leaf has its complete retained WOTS keygen witness. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeCatalog PersistentGrind WotsReferenceRoot.

op wots_catalog h s seed layer tree (c : node_catalog) =
  forall i leaf, c.[(0,i)]=Some leaf => wots_root h s seed layer tree i leaf.

lemma wots_catalog_empty h s seed layer tree : wots_catalog h s seed layer tree empty.
proof. rewrite /wots_catalog; smt(emptyE). qed.

lemma wots_catalog_extends h h' s s' seed layer tree c :
  extends h h' => extends s s' => wots_catalog h s seed layer tree c =>
  wots_catalog h' s' seed layer tree c.
proof. rewrite /wots_catalog; smt(wots_root_extends). qed.

lemma wots_catalog_leaf h s seed layer tree c i leaf :
  wots_catalog h s seed layer tree c => wots_root h s seed layer tree i leaf =>
  wots_catalog h s seed layer tree c.[(0,i)<-leaf].
proof. rewrite /wots_catalog; smt(get_setE). qed.

lemma wots_catalog_parent h s seed layer tree c height i value :
  0<height => wots_catalog h s seed layer tree c =>
  wots_catalog h s seed layer tree c.[(height,i)<-value].
proof. rewrite /wots_catalog; smt(get_setE). qed.

lemma wots_catalog_target h s seed layer tree c i :
  (0,i) \in c => wots_catalog h s seed layer tree c =>
  wots_root h s seed layer tree i (catalog_grid c 0 i).
proof. rewrite /wots_catalog /catalog_grid; smt(get_some). qed.
