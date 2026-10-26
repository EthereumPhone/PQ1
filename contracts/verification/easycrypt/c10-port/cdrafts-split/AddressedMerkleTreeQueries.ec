(* Actual Merkle construction adds only canonical WOTS and parent queries. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawPathReplay DyadicStack StackProjection StackAlignment NodeCatalog NodeCatalogDomain.
require import CatalogStack CatalogForest CatalogMerge CatalogOracle MerkleCatalogObserver MerkleBuildWitness BuildRootProjection.
require import WotsCatalog AddressedWotsCanonicity AddressedMerkleCanonicity AddressedTreeLog AddressedMerkleCatalog.

lemma merkle_catalog_canonical_queries seed0 layer0 tree0 base :
  hoare [MerkleCatalogObserver(PreparationView(Independent)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ 0<=layer0<4294967296 /\ 0<=tree0<2^64 /\
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_merkle_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 res.`3 /\
    forest_references res.`3 res.`2 512 /\ catalog_exact res.`3 512 /\
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  proc; while (seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ 0<=layer0<4294967296 /\ 0<=tree0<2^64 /\
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries /\
    size stack<=kp /\ 0 <= kp <= 512 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = kp /\ catalog_exact catalog kp /\
    canonical_merkle_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 catalog /\
    forest_references catalog stack kp).
  + wp; while (seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ 0<=layer0<4294967296 /\ 0<=tree0<2^64 /\
      canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries /\
      0<=height /\ height+size stack<=kp /\ 0 <= kp < 512 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = kp+1 /\
      catalog_partial catalog (kp+1) height /\
      canonical_merkle_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 catalog /\
      forest_references catalog stack (kp+1-2^height) /\
      catalog.[(height,kp %/ (2^height))] = Some current).
    - exists* catalog, stack, current, height, kp;
        elim* => cat0 st0 cur0 h0 kp0.
      wp; call (hash_records_canonical_merkle seed0 layer0 tree0 cat0 base
        (merkle_pair seed0 layer0 tree0 (h0+1) (kp0 %/ (2^(h0+1)))
          (head ([],0) st0).`1 cur0)).
      auto; move=> &hr hi.
      have hp := projected_catalog_pop st0 [] h0 (kp0+1) cat0.
      have hm : forall table secret d,
        canonical_merkle_catalog table secret seed0 layer0 tree0 cat0 =>
        table.[merkle_pair seed0 layer0 tree0 (h0+1) (kp0 %/ (2^(h0+1)))
          (head ([],0) st0).`1 cur0] = Some d =>
        let cat' = cat0.[(h0+1,kp0 %/ (2^(h0+1))) <- node d] in
          canonical_merkle_catalog table secret seed0 layer0 tree0 cat' /\
          forest_references cat' (behead st0) (kp0+1-2^(h0+1)) /\
          cat'.[(h0+1,kp0 %/ (2^(h0+1)))] = Some (node d).
      + move=> table secret d hs hd.
        apply (canonical_merkle_merge_recorded table secret seed0 layer0 tree0
          cat0 st0 cur0 h0 (kp0+1) d); smt().
      have hstep : forall table secret d,
        canonical_merkle_catalog table secret seed0 layer0 tree0 cat0 =>
        table.[merkle_pair seed0 layer0 tree0 (h0+1) (kp0 %/ (2^(h0+1)))
          (head ([],0) st0).`1 cur0] = Some d =>
        let cat' = cat0.[(h0+1,kp0 %/ (2^(h0+1))) <- node d] in
          active_stack (map snd (behead st0)) (h0+1) /\
          stack_mass (map snd (behead st0)) + 2^(h0+1) = kp0+1 /\
          catalog_partial cat' (kp0+1) (h0+1) /\
          canonical_merkle_catalog table secret seed0 layer0 tree0 cat' /\
          forest_references cat' (behead st0) (kp0+1-2^(h0+1)) /\
          cat'.[(h0+1,kp0 %/ (2^(h0+1)))] = Some (node d).
      + move=> table secret d hs hd.
        have hparts := hp (node d) _ _ _ _ _ _; try by smt().
      have hinput : seed{hr} ++ address layer{hr} tree{hr} 2 0 0
          (height{hr}+1) (kp{hr} %/ (2^(height{hr}+1))) ++
          pad (head ([],0) stack{hr}).`1 ++ pad current{hr} =
          merkle_pair seed0 layer0 tree0 (h0+1) (kp0 %/ (2^(h0+1)))
            (head ([],0) st0).`1 cur0.
      + rewrite /merkle_pair; smt().
      have hcinput := canonical_merkle_merge_member Independent.rawhistory{hr}
        Independent.secrethistory{hr} seed0 layer0 tree0 cat0 st0 cur0 h0 (kp0+1).
      smt(size_behead size_ge0 size_eq0).
    exists* catalog,kp; elim* => cat0 kp0.
    wp; call (leaf_records_canonical_merkle seed0 layer0 tree0 kp0 cat0 base).
    auto; rewrite expr0 ?divz1.
    move=> &hr hi; split; first by rewrite /wots_address_valid; smt().
    move=> _ value queries table private hs; split.
    - have hf := catalog_leaf_fresh cat0 kp0 _; first by smt().
      have hp := catalog_partial_leaf cat0 kp0 value.
      have hsound := catalog_sound_leaf table (merkle_pair seed0 layer0 tree0)
        cat0 kp0 value _ hf _; first 2 by move: hs; rewrite /canonical_merkle_catalog; smt().
      have hforest := forest_leaf_insert cat0 stack{hr} kp0 value hf _; first smt().
      have horigin := wots_catalog_leaf table private seed0 layer0 tree0 cat0 kp0 value _ _;
        first 2 by move: hs; rewrite /canonical_merkle_catalog; smt().
      rewrite /canonical_merkle_catalog; smt(carry_initial).
    move=> queries' table' cat cur h st hx hin.
    have ha : active_stack (map snd st) h by smt().
    have hmass : stack_mass (map snd st)+2^h=kp0+1 by smt().
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    have hf := projected_catalog_finish st [] h (kp0+1) cat ha _ hmass _.
    + smt().
    + smt().
    have hd := active_stack_alignment (map snd st) h (kp0+1) ha hmass.
    move: hp; rewrite /=; smt().
  auto; rewrite /canonical_merkle_catalog; smt(catalog_exact_empty catalog_sound_empty wots_catalog_empty).
qed.

lemma merkle_witness_canonical_queries seed0 layer0 tree0 base :
  hoare [MerkleBuildWitness(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=layer0<4294967296 /\ 0<=tree0<2^64 /\
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  conseq (merkle_catalog_projection (PreparationView(Independent)))
    (merkle_catalog_canonical_queries seed0 layer0 tree0 base).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma raw_merkle_build_canonical_queries seed0 layer0 tree0 base :
  hoare [RawMerkle(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=layer0<4294967296 /\ 0<=tree0<2^64 /\
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  conseq (merkle_build_witness_projection (PreparationView(Independent)))
    (merkle_witness_canonical_queries seed0 layer0 tree0 base).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma raw_keygen_root_canonical_queries seed0 layer0 tree0 base :
  hoare [RawKeygen(PreparationView(Independent)).root :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=layer0<4294967296 /\ 0<=tree0<2^64 /\
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  conseq (merkle_build_root_projection (PreparationView(Independent)))
    (raw_merkle_build_canonical_queries seed0 layer0 tree0 base).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},0); smt().
  smt().
qed.

