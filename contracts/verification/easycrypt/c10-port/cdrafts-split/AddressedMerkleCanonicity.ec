(* A Merkle parent input is determined by its address and retained WOTS leaves.
   Tree construction must establish these catalog premises from actual calls. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawPathReplay NodeCatalog WotsCatalog WotsRootDeterminism.
require import PersistentGrind AcceptedContexts ClientGuessCandidates ForsInputSeparation.
require import AddressedInputFields AddressedNodeCollision.

op merkle_address_valid layer tree parent =
  0<=layer<4294967296 /\ 0<=tree<2^64 /\ 0<=parent<4294967296.
op canonical_merkle_catalog h s seed layer tree c =
  catalog_sound h (merkle_pair seed layer tree) c /\ wots_catalog h s seed layer tree c.
op canonical_merkle_pair_input seed layer tree level parent c =
  merkle_pair seed layer tree level parent
    (catalog_grid c (level-1) (2*parent)) (catalog_grid c (level-1) (2*parent+1)).
op canonical_merkle_pair_supported h s seed layer tree level parent c =
  canonical_merkle_catalog h s seed layer tree c /\
  (level-1,2*parent) \in c /\ (level-1,2*parent+1) \in c.

lemma canonical_merkle_catalog_extends h h' s s' seed layer tree c :
  extends h h' => extends s s' => canonical_merkle_catalog h s seed layer tree c =>
  canonical_merkle_catalog h' s' seed layer tree c.
proof.
  move=> hh hs [hc hw]; split; first exact (catalog_sound_history_extends h h' _ c hh hc).
  exact (wots_catalog_extends h h' s s' seed layer tree c hh hs hw).
qed.

lemma canonical_merkle_pair_extends h h' s s' seed layer tree level parent c :
  extends h h' => extends s s' => canonical_merkle_pair_supported h s seed layer tree level parent c =>
  canonical_merkle_pair_supported h' s' seed layer tree level parent c.
proof. rewrite /canonical_merkle_pair_supported; smt(canonical_merkle_catalog_extends). qed.

lemma canonical_merkle_pair_same_coordinate h s seed layer tree level parent c c' :
  0<level => canonical_merkle_pair_supported h s seed layer tree level parent c =>
  canonical_merkle_pair_supported h s seed layer tree level parent c' =>
  canonical_merkle_pair_input seed layer tree level parent c=canonical_merkle_pair_input seed layer tree level parent c'.
proof.
  move=> hl [[hc hw] [hm hn]] [[hc' hw'] [hm' hn']].
  have hh := wots_catalog_common_nodes h s seed layer tree c c' (level-1) hc hc' hw hw' _; first smt().
  by rewrite /canonical_merkle_pair_input (hh (2*parent) hm hm') (hh (2*parent+1) hn hn').
qed.

lemma canonical_merkle_pair_unique h s seed layer tree level parent c layer' tree' level' parent' c' :
  size seed=32 => merkle_address_valid layer tree parent => merkle_address_valid layer' tree' parent' =>
  0<level<4294967296 => 0<level'<4294967296 =>
  canonical_merkle_pair_supported h s seed layer tree level parent c =>
  canonical_merkle_pair_supported h s seed layer' tree' level' parent' c' =>
  same_node_address (canonical_merkle_pair_input seed layer tree level parent c)
    (canonical_merkle_pair_input seed layer' tree' level' parent' c') =>
  canonical_merkle_pair_input seed layer tree level parent c=canonical_merkle_pair_input seed layer' tree' level' parent' c'.
proof.
  move=> hs hv hv' hl hl' hc hc' he.
  have hp : same_node_address
    (seed++address layer tree 2 0 0 level parent++
      (pad (catalog_grid c (level-1) (2*parent))++pad (catalog_grid c (level-1) (2*parent+1))))
    (seed++address layer' tree' 2 0 0 level' parent'++
      (pad (catalog_grid c' (level'-1) (2*parent'))++pad (catalog_grid c' (level'-1) (2*parent'+1))))
    by move: he; rewrite /canonical_merkle_pair_input /merkle_pair -!catA.
  have ha : address layer tree 2 0 0 level parent=address layer' tree' 2 0 0 level' parent'
    by have hh := addressed_prefix_coordinates seed (address layer tree 2 0 0 level parent)
      _ seed (address layer' tree' 2 0 0 level' parent') _ hs hs
      (raw_address_width _ _ _ _ _ _ _) (raw_address_width _ _ _ _ _ _ _) hp; smt().
  have hf := address_fields_injective layer tree 2 0 0 level parent layer' tree' 2 0 0 level' parent'.
  have heq : layer=layer' /\ tree=tree' /\ level=level' /\ parent=parent'
    by move: hv hv'; rewrite /merkle_address_valid; smt().
  have hh := canonical_merkle_pair_same_coordinate h s seed layer tree level parent c c' _ hc _;
    first 2 smt().
  smt().
qed.

op canonical_merkle_input h s seed x =
  exists layer tree level parent c,
    merkle_address_valid layer tree parent /\ 0<level<4294967296 /\
    canonical_merkle_pair_supported h s seed layer tree level parent c /\
    x=canonical_merkle_pair_input seed layer tree level parent c.

lemma canonical_merkle_input_extends h h' s s' seed x :
  extends h h' => extends s s' => canonical_merkle_input h s seed x =>
  canonical_merkle_input h' s' seed x.
proof.
  move=> hh hs [layer tree level parent c [hv [hl [hc hx]]]].
  exists layer tree level parent c; smt(canonical_merkle_pair_extends).
qed.

lemma canonical_merkle_input_unique h s seed x y :
  size seed=32 => canonical_merkle_input h s seed x => canonical_merkle_input h s seed y =>
  same_node_address x y => x=y.
proof.
  move=> hs [layer tree level parent c [hv [hl [hc hx]]]]
    [layer' tree' level' parent' c' [hv' [hl' [hc' hy]]]] he.
  smt(canonical_merkle_pair_unique).
qed.
