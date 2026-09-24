(* Retained WOTS keygen witnesses have one value in a fixed pair of tables. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeCatalog WotsReferenceRoot WotsCatalog.
require import WotsReference WotsLeafReference CatalogDeterminism RawPathReplay.

lemma wots_root_unique h s seed layer tree index root root' :
  wots_root h s seed layer tree index root => wots_root h s seed layer tree index root' => root=root'.
proof. rewrite /wots_root; smt(). qed.

lemma wots_catalog_common_nodes h s seed layer tree c c' level :
  catalog_sound h (RawPathReplay.merkle_pair seed layer tree) c =>
  catalog_sound h (RawPathReplay.merkle_pair seed layer tree) c' =>
  wots_catalog h s seed layer tree c => wots_catalog h s seed layer tree c' =>
  0<=level => forall i, (level,i) \in c => (level,i) \in c' =>
    catalog_grid c level i = catalog_grid c' level i.
proof.
  move=> hs hs' hw hw' hl.
  apply (catalog_common_nodes_equal h (RawPathReplay.merkle_pair seed layer tree) c c' level hs hs' _ hl).
  move=> i hi hi'.
  have hroot := wots_catalog_target h s seed layer tree c i hi hw.
  have hroot' := wots_catalog_target h s seed layer tree c' i hi' hw'.
  exact (wots_root_unique h s seed layer tree i _ _ hroot hroot').
qed.
