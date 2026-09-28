(* Complete FORS references have one root for a fixed coordinate and tables. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawForsPathReplay NodeCatalog NodeCatalogDomain StackPowers.
require import ForsRootWitness SecretLeafOrigins CatalogDeterminism.

lemma fors_root_witness_unique h s seed ht tree root root' :
  fors_root_witness h s seed ht tree root => fors_root_witness h s seed ht tree root' => root=root'.
proof.
  move=> [c [hc [hs [hw [ho hr]]]]] [c' [hc' [hs' [hw' [ho' hr']]]]].
  have hl : forall i, (0,i) \in c => (0,i) \in c' => catalog_grid c 0 i=catalog_grid c' 0 i.
  + move=> i hi hi'.
    have he := get_some c (0,i) hi.
    have he' := get_some c' (0,i) hi'.
    have [sd d [hpriv [hpub hv]]] := ho i (oget c.[(0,i)]) he.
    have [sd' d' [hpriv' [hpub' hv']]] := ho' i (oget c'.[(0,i)]) he'.
    rewrite /catalog_grid; smt().
  have hm : (11,0) \in c by apply hc; rewrite /node_due /node_right_edge stack_pow2_11; smt().
  have hm' : (11,0) \in c' by apply hc'; rewrite /node_due /node_right_edge stack_pow2_11; smt().
  have he := catalog_common_nodes_equal h (fors_pair seed ht tree) c c' 11 hs hs' hl _ 0 hm hm'; first smt().
  smt().
qed.
