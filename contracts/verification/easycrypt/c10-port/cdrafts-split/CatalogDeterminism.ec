(* Sound catalogs with the same leaves agree at every common recorded node. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeCatalog.

lemma catalog_common_nodes_equal h f c c' level :
  catalog_sound h f c => catalog_sound h f c' =>
  (forall i, (0,i) \in c => (0,i) \in c' => catalog_grid c 0 i = catalog_grid c' 0 i) =>
  0 <= level => forall i, (level,i) \in c => (level,i) \in c' =>
    catalog_grid c level i = catalog_grid c' level i.
proof.
  move=> hs hs' hleaf hl.
  elim: level hl => [|level hl ih].
  + exact hleaf.
  move=> i hc hc'.
  have hlink : catalog_link h f c (level+1) i by have hh := hs (level+1) i hc; smt().
  have hlink' : catalog_link h f c' (level+1) i by have hh := hs' (level+1) i hc'; smt().
  move: hlink; rewrite /catalog_link /=; move=> [lval rval d [hleft [hright [hd hout]]]].
  move: hlink'; rewrite /catalog_link /=; move=> [lval' rval' d' [hleft' [hright' [hd' hout']]]].
  have hle := ih (2*i) _ _; first 2 smt(domE).
  have hre := ih (2*i+1) _ _; first 2 smt(domE).
  move: hle hre; rewrite /catalog_grid hleft hleft' hright hright' !oget_some.
  move=> hlr hrr; rewrite /catalog_grid hout hout' !oget_some; smt().
qed.
