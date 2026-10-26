(* Actual Merkle leaf and merge steps preserve the combined query family. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawPathReplay.
require import PersistentGrind AcceptedContexts NodeCatalog NodeCatalogDomain DyadicStack StackProjection StackAlignment.
require import NodeGridIndex CatalogForest CatalogMerge CatalogOracle WotsCatalog WotsCatalogOracle WotsReferenceRoot.
require import AddressedWotsCanonicity AddressedMerkleCanonicity AddressedTreeLog.

lemma canonical_merkle_merge_member h s seed layer tree c stack current height n :
  0<=layer<4294967296 => 0<=tree<2^64 => 0<=height<512 => 0<n<=512 =>
  canonical_merkle_catalog h s seed layer tree c =>
  active_stack (map snd stack) height => stack<>[] => (head ([],0) stack).`2=height =>
  stack_mass (map snd stack)+2^height=n =>
  forest_references c stack (n-2^height) =>
  c.[(height,(n-1) %/ (2^height))]=Some current =>
  canonical_merkle_input h s seed
    (merkle_pair seed layer tree (height+1) ((n-1) %/ (2^(height+1)))
      (head ([],0) stack).`1 current).
proof.
  move=> hht htree hh hn hc ha hs he hm hf hcur.
  have [ha' hm'] := projected_carry_pop stack [] height ha hs he.
  have hm'' : stack_mass (map snd (behead stack))+2^(height+1)=n by smt().
  have hd := active_stack_alignment (map snd (behead stack)) (height+1) n ha' hm''.
  have [hz [hleft hrest]] := forest_pop c stack n height hf hs he.
  have [hri hli] := aligned_pair_indices n height _ hd; first smt().
  have hp := pow2_pos (height+1) _; first smt().
  have hi : 0<=(n-1) %/ (2^(height+1))<4294967296.
  + rewrite divz_ge0 1:hp ltz_divLR 1:hp; smt().
  rewrite /canonical_merkle_input.
  exists layer tree (height+1) ((n-1) %/ (2^(height+1))) c.
  rewrite /merkle_address_valid /canonical_merkle_pair_supported /canonical_merkle_pair_input.
  have hl : catalog_grid c height (2*((n-1) %/ (2^(height+1))))=(head ([],0) stack).`1
    by rewrite /catalog_grid; smt(oget_some).
  have hr : catalog_grid c height (2*((n-1) %/ (2^(height+1)))+1)=current
    by rewrite /catalog_grid; smt(oget_some).
  smt(domE).
qed.

lemma hash_records_canonical_merkle seed layer tree c base x0 :
  hoare [Independent.hash :
    x=x0 /\ canonical_merkle_catalog Independent.rawhistory Independent.secrethistory seed layer tree c /\
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed base Independent.queries /\
    canonical_merkle_input Independent.rawhistory Independent.secrethistory seed x0 ==>
    canonical_merkle_catalog Independent.rawhistory Independent.secrethistory seed layer tree c /\
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed base Independent.queries /\
    Independent.rawhistory.[x0]=Some res].
proof.
  proc; sp 1; if; auto;
    smt(canonical_merkle_catalog_extends canonical_tree_log_push_extends canonical_tree_merkle_member
      extends_insert extends_refl get_set_sameE domE).
qed.

lemma leaf_records_canonical_merkle seed0 layer0 tree0 index0 c base :
  hoare [RawKeygen(PreparationView(Independent)).leaf :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=index0 /\
    wots_address_valid layer0 tree0 index0 0 0 /\
    canonical_merkle_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 c /\
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_merkle_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 c /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 index0 res /\
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  have hc : hoare [RawKeygen(PreparationView(Independent)).leaf :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=index0 /\
    canonical_merkle_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 c ==>
    canonical_merkle_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 c /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 index0 res].
  + conseq (leaf_records_wots_catalog seed0 layer0 tree0 index0 c)
      (leaf_keeps_catalog RawKeygen (merkle_pair seed0 layer0 tree0) c);
      rewrite /canonical_merkle_catalog; smt().
  conseq hc (leaf_appends_canonical_tree_log seed0 layer0 tree0 index0 base); smt().
qed.

lemma canonical_merkle_merge_recorded h s seed layer tree c stack current height n d :
  active_stack (map snd stack) height => stack<>[] => (head ([],0) stack).`2=height =>
  stack_mass (map snd stack)+2^height=n => catalog_partial c n height =>
  canonical_merkle_catalog h s seed layer tree c => forest_references c stack (n-2^height) =>
  c.[(height,(n-1) %/ (2^height))]=Some current =>
  h.[merkle_pair seed layer tree (height+1) ((n-1) %/ (2^(height+1)))
    (head ([],0) stack).`1 current]=Some d =>
  let c'=c.[(height+1,(n-1) %/ (2^(height+1))) <- node d] in
    canonical_merkle_catalog h s seed layer tree c' /\
    forest_references c' (behead stack) (n-2^(height+1)) /\
    c'.[(height+1,(n-1) %/ (2^(height+1)))]=Some (node d).
proof.
  move=> ha hs he hm hp [hc ho] hf hcur hd.
  have hr := catalog_merge_recorded h (merkle_pair seed layer tree) c stack current height n d
    ha hs he hm hp hc hf hcur hd.
  have hz : 0<=height by move: ha; rewrite /active_stack; smt().
  have ho' := wots_catalog_parent h s seed layer tree c (height+1)
    ((n-1) %/ (2^(height+1))) (node d) _ ho; first smt().
  rewrite /canonical_merkle_catalog; smt().
qed.

