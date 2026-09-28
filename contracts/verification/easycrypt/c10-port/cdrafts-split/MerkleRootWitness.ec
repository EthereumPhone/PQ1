(* A complete retained Merkle/WOTS catalog fixes the root across later calls. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawPathReplay PersistentGrind.
require import NodeCatalog NodeCatalogDomain StackPowers WotsCatalog WotsRootDeterminism.

op merkle_root_witness h s seed layer tree root =
  exists c, catalog_exact c 512 /\ catalog_sound h (merkle_pair seed layer tree) c /\
    wots_catalog h s seed layer tree c /\ root=catalog_grid c 9 0.

lemma merkle_root_witness_extends h h' s s' seed layer tree root :
  extends h h' => extends s s' => merkle_root_witness h s seed layer tree root =>
  merkle_root_witness h' s' seed layer tree root.
proof.
  move=> hh hs [c [hc [hcat [hw hr]]]].
  have hce := catalog_sound_extend h h' (merkle_pair seed layer tree) c c hh (catalog_extension_refl c) hcat.
  have hwe := wots_catalog_extends h h' s s' seed layer tree c hh hs hw.
  rewrite /merkle_root_witness; exists c; smt().
qed.

lemma merkle_root_witness_unique h s seed layer tree root root' :
  merkle_root_witness h s seed layer tree root => merkle_root_witness h s seed layer tree root' => root=root'.
proof.
  move=> [c [hc [hs [hw hr]]]] [c' [hc' [hs' [hw' hr']]]].
  have hm : (9,0) \in c by apply hc; rewrite /node_due /node_right_edge stack_pow2_9; smt().
  have hm' : (9,0) \in c' by apply hc'; rewrite /node_due /node_right_edge stack_pow2_9; smt().
  have he := wots_catalog_common_nodes h s seed layer tree c c' 9 hs hs' hw hw' _ 0 hm hm'; first smt().
  smt().
qed.
