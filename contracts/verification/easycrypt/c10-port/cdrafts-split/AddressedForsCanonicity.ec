(* FORS leaf and parent inputs are determined by fixed public/private history.
   The special transmitted-root hash is deliberately outside this family. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawSignature RawForsPathReplay ForsPrivateLeaves.
require import NodeCatalog CatalogDeterminism SecretLeafOrigins PersistentGrind AcceptedContexts.
require import ClientGuessCandidates ForsInputSeparation AddressedInputFields AddressedNodeCollision.

op fors_address_valid ht tree index = 0<=ht<2^64 /\ 0<=tree<13 /\ 0<=index<4294967296.
op canonical_fors_leaf_input s seed ht tree index =
  fors_leaf_input seed ht tree index (node (oget s.[fors_private_key ht tree index])).
op canonical_fors_catalog h s seed ht tree c =
  catalog_sound h (fors_pair seed ht tree) c /\
  secret_leaf_origins h s (fors_leaf_input seed ht tree) (fors_private_key ht tree) c.
op canonical_fors_pair_input seed ht tree level parent c =
  fors_pair seed ht tree level parent
    (catalog_grid c (level-1) (2*parent)) (catalog_grid c (level-1) (2*parent+1)).
op canonical_fors_pair_supported h s seed ht tree level parent c =
  canonical_fors_catalog h s seed ht tree c /\
  (level-1,2*parent) \in c /\ (level-1,2*parent+1) \in c.

lemma canonical_fors_leaf_extends s s' seed ht tree index :
  extends s s' => fors_private_key ht tree index \in s =>
  canonical_fors_leaf_input s' seed ht tree index=canonical_fors_leaf_input s seed ht tree index.
proof. rewrite /canonical_fors_leaf_input /extends; smt(). qed.

lemma canonical_fors_leaf_unique s seed ht tree index ht' tree' index' :
  size seed=32 => fors_address_valid ht tree index => fors_address_valid ht' tree' index' =>
  same_node_address (canonical_fors_leaf_input s seed ht tree index)
    (canonical_fors_leaf_input s seed ht' tree' index') =>
  canonical_fors_leaf_input s seed ht tree index=canonical_fors_leaf_input s seed ht' tree' index'.
proof.
  move=> hs hv hv'; rewrite /canonical_fors_leaf_input /fors_leaf_input => he.
  have ha : address 0 ht 3 tree 0 0 index=address 0 ht' 3 tree' 0 0 index'
    by have hp := addressed_prefix_coordinates seed (address 0 ht 3 tree 0 0 index)
      _ seed (address 0 ht' 3 tree' 0 0 index') _ hs hs
      (raw_address_width _ _ _ _ _ _ _) (raw_address_width _ _ _ _ _ _ _) he; smt().
  have hf := address_fields_injective 0 ht 3 tree 0 0 index 0 ht' 3 tree' 0 0 index'.
  move: hv hv'; rewrite /fors_address_valid; smt().
qed.

lemma canonical_fors_catalog_extends h h' s s' seed ht tree c :
  extends h h' => extends s s' => canonical_fors_catalog h s seed ht tree c =>
  canonical_fors_catalog h' s' seed ht tree c.
proof.
  move=> hh hs [hc ho]; split; first exact (catalog_sound_history_extends h h' _ c hh hc).
  apply (secret_leaf_private_extends h' s s' _ _ c hs).
  exact (secret_leaf_public_extends h h' s _ _ c hh ho).
qed.

lemma canonical_fors_common_nodes h s seed ht tree c c' level :
  canonical_fors_catalog h s seed ht tree c => canonical_fors_catalog h s seed ht tree c' =>
  0<=level => forall i, (level,i) \in c => (level,i) \in c' =>
    catalog_grid c level i=catalog_grid c' level i.
proof.
  move=> [hc ho] [hc' ho'] hl.
  apply (catalog_common_nodes_equal h (fors_pair seed ht tree) c c' level hc hc' _ hl).
  move=> i hi hi'.
  have he := get_some c (0,i) hi.
  have he' := get_some c' (0,i) hi'.
  have [sd d [hpriv [hpub hv]]] := ho i (oget c.[(0,i)]) he.
  have [sd' d' [hpriv' [hpub' hv']]] := ho' i (oget c'.[(0,i)]) he'.
  rewrite /catalog_grid; smt().
qed.

lemma canonical_fors_pair_extends h h' s s' seed ht tree level parent c :
  extends h h' => extends s s' => canonical_fors_pair_supported h s seed ht tree level parent c =>
  canonical_fors_pair_supported h' s' seed ht tree level parent c.
proof. rewrite /canonical_fors_pair_supported; smt(canonical_fors_catalog_extends). qed.

lemma canonical_fors_pair_same_coordinate h s seed ht tree level parent c c' :
  0<level => canonical_fors_pair_supported h s seed ht tree level parent c =>
  canonical_fors_pair_supported h s seed ht tree level parent c' =>
  canonical_fors_pair_input seed ht tree level parent c=canonical_fors_pair_input seed ht tree level parent c'.
proof.
  move=> hl [hc [hm hn]] [hc' [hm' hn']].
  have hs := canonical_fors_common_nodes h s seed ht tree c c' (level-1) hc hc' _; first smt().
  by rewrite /canonical_fors_pair_input (hs (2*parent) hm hm') (hs (2*parent+1) hn hn').
qed.

lemma canonical_fors_pair_unique h s seed ht tree level parent c ht' tree' level' parent' c' :
  size seed=32 => fors_address_valid ht tree parent => fors_address_valid ht' tree' parent' =>
  0<level<4294967296 => 0<level'<4294967296 =>
  canonical_fors_pair_supported h s seed ht tree level parent c =>
  canonical_fors_pair_supported h s seed ht' tree' level' parent' c' =>
  same_node_address (canonical_fors_pair_input seed ht tree level parent c)
    (canonical_fors_pair_input seed ht' tree' level' parent' c') =>
  canonical_fors_pair_input seed ht tree level parent c=canonical_fors_pair_input seed ht' tree' level' parent' c'.
proof.
  move=> hs hv hv' hl hl' hc hc' he.
  have hp : same_node_address
    (seed++address 0 ht 3 tree 0 level parent++
      (pad (catalog_grid c (level-1) (2*parent))++pad (catalog_grid c (level-1) (2*parent+1))))
    (seed++address 0 ht' 3 tree' 0 level' parent'++
      (pad (catalog_grid c' (level'-1) (2*parent'))++pad (catalog_grid c' (level'-1) (2*parent'+1))))
    by move: he; rewrite /canonical_fors_pair_input /fors_pair -!catA.
  have ha : address 0 ht 3 tree 0 level parent=address 0 ht' 3 tree' 0 level' parent'
    by have hh := addressed_prefix_coordinates seed (address 0 ht 3 tree 0 level parent)
      _ seed (address 0 ht' 3 tree' 0 level' parent') _ hs hs
      (raw_address_width _ _ _ _ _ _ _) (raw_address_width _ _ _ _ _ _ _) hp; smt().
  have hf := address_fields_injective 0 ht 3 tree 0 level parent 0 ht' 3 tree' 0 level' parent'.
  have heq : ht=ht' /\ tree=tree' /\ level=level' /\ parent=parent'
    by move: hv hv'; rewrite /fors_address_valid; smt().
  have hh := canonical_fors_pair_same_coordinate h s seed ht tree level parent c c' _ hc _;
    first 2 smt().
  smt().
qed.

lemma canonical_fors_leaf_pair_separate s seed ht tree index ht' tree' level parent c :
  size seed=32 => 0<level<4294967296 =>
  !same_node_address (canonical_fors_leaf_input s seed ht tree index)
    (canonical_fors_pair_input seed ht' tree' level parent c).
proof.
  move=> hs hl; apply/negP => he.
  have hp : same_node_address
    (seed++address 0 ht 3 tree 0 0 index++pad (node (oget s.[fors_private_key ht tree index])))
    (seed++address 0 ht' 3 tree' 0 level parent++
      (pad (catalog_grid c (level-1) (2*parent))++pad (catalog_grid c (level-1) (2*parent+1))))
    by move: he; rewrite /canonical_fors_leaf_input /fors_leaf_input /canonical_fors_pair_input /fors_pair -!catA.
  have ha : address 0 ht 3 tree 0 0 index=address 0 ht' 3 tree' 0 level parent
    by have hh := addressed_prefix_coordinates seed (address 0 ht 3 tree 0 0 index)
      _ seed (address 0 ht' 3 tree' 0 level parent) _ hs hs
      (raw_address_width _ _ _ _ _ _ _) (raw_address_width _ _ _ _ _ _ _) hp; smt().
  have hf : address_field_bytes (address 0 ht 3 tree 0 0 index)=
    address_field_bytes (address 0 ht' 3 tree' 0 level parent) by rewrite ha.
  rewrite !address_field_bytes_exact in hf; smt(be4_injective).
qed.

op canonical_fors_input h s seed x =
  (exists ht tree index,
    fors_address_valid ht tree index /\ fors_private_key ht tree index \in s /\
    x=canonical_fors_leaf_input s seed ht tree index) \/
  (exists ht tree level parent c,
    fors_address_valid ht tree parent /\ 0<level<4294967296 /\
    canonical_fors_pair_supported h s seed ht tree level parent c /\
    x=canonical_fors_pair_input seed ht tree level parent c).

lemma canonical_fors_input_extends h h' s s' seed x :
  extends h h' => extends s s' => canonical_fors_input h s seed x =>
  canonical_fors_input h' s' seed x.
proof.
  move=> hh hs; rewrite /canonical_fors_input; move=> [hl|hp].
  + elim hl => ht tree index [hv [hk hx]]; left; exists ht tree index.
    have hk' : fors_private_key ht tree index \in s' by move: hs; rewrite /extends; smt(domE).
    smt(canonical_fors_leaf_extends).
  elim hp => ht tree level parent c [hv [hl [hc hx]]]; right; exists ht tree level parent c.
  smt(canonical_fors_pair_extends).
qed.

lemma canonical_fors_input_unique h s seed x y :
  size seed=32 => canonical_fors_input h s seed x => canonical_fors_input h s seed y =>
  same_node_address x y => x=y.
proof.
  move=> hs; rewrite /canonical_fors_input; move=> [hl|hp] [hl'|hp'] he.
  + elim hl => ht tree index [hv [hk hx]].
    elim hl' => ht' tree' index' [hv' [hk' hy]].
    smt(canonical_fors_leaf_unique).
  + elim hl => ht tree index [hv [hk hx]].
    elim hp' => ht' tree' level' parent' c' [hv' [hl' [hc' hy]]].
    smt(canonical_fors_leaf_pair_separate).
  + elim hp => ht tree level parent c [hv [hl [hc hx]]].
    elim hl' => ht' tree' index' [hv' [hk' hy]].
    have hsym : same_node_address y x by move: he; rewrite /same_node_address; smt().
    smt(canonical_fors_leaf_pair_separate).
  elim hp => ht tree level parent c [hv [hl [hc hx]]].
  elim hp' => ht' tree' level' parent' c' [hv' [hl' [hc' hy]]].
  smt(canonical_fors_pair_unique).
qed.
