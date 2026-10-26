(* Every actual FORS tree-builder query is canonical, including memo hits. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import RawForsPathReplay DyadicStack StackProjection StackAlignment NodeCatalog NodeCatalogDomain.
require import CatalogStack CatalogForest CatalogMerge CatalogOracle ForsCatalogObserver.
require import ForsPrivateLeaves SecretLeafOrigins AddressedForsCanonicity AddressedForsLog AddressedForsCatalog.
require import ForsBuildWitness.

lemma fors_catalog_canonical_queries seed0 ht0 tree0 base :
  hoare [ForsCatalogObserver(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_fors_catalog Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 res.`3 /\
    forest_references res.`3 res.`1 2048 /\ catalog_exact res.`3 2048 /\
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  proc; while (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries /\
    size stack<=j /\ 0 <= j <= 2048 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = j /\ catalog_exact catalog j /\
    canonical_fors_catalog Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 catalog /\
    forest_references catalog stack j).
  + wp; while (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
      canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries /\
      0<=height /\ height+size stack<=j /\ 0 <= j < 2048 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = j+1 /\
      catalog_partial catalog (j+1) height /\
      canonical_fors_catalog Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 catalog /\
      forest_references catalog stack (j+1-2^height) /\
      catalog.[(height,j %/ (2^height))] = Some current).
    - exists* catalog, stack, current, height, j;
        elim* => cat0 st0 cur0 h0 j0.
      wp; call (hash_records_canonical_fors seed0 ht0 tree0 cat0 base
        (fors_pair seed0 ht0 tree0 (h0+1) (j0 %/ (2^(h0+1)))
          (head ([],0) st0).`1 cur0)).
      auto; move=> &hr hi.
      have hp := projected_catalog_pop st0 [] h0 (j0+1) cat0.
      have hm : forall table secret d,
        canonical_fors_catalog table secret seed0 ht0 tree0 cat0 =>
        table.[fors_pair seed0 ht0 tree0 (h0+1) (j0 %/ (2^(h0+1)))
          (head ([],0) st0).`1 cur0] = Some d =>
        let cat' = cat0.[(h0+1,j0 %/ (2^(h0+1))) <- node d] in
          canonical_fors_catalog table secret seed0 ht0 tree0 cat' /\
          forest_references cat' (behead st0) (j0+1-2^(h0+1)) /\
          cat'.[(h0+1,j0 %/ (2^(h0+1)))] = Some (node d).
      + move=> table secret d hs hd.
        apply (canonical_fors_merge_recorded table secret seed0 ht0 tree0
          cat0 st0 cur0 h0 (j0+1) d); smt().
      have hstep : forall table secret d,
        canonical_fors_catalog table secret seed0 ht0 tree0 cat0 =>
        table.[fors_pair seed0 ht0 tree0 (h0+1) (j0 %/ (2^(h0+1)))
          (head ([],0) st0).`1 cur0] = Some d =>
        let cat' = cat0.[(h0+1,j0 %/ (2^(h0+1))) <- node d] in
          active_stack (map snd (behead st0)) (h0+1) /\
          stack_mass (map snd (behead st0)) + 2^(h0+1) = j0+1 /\
          catalog_partial cat' (j0+1) (h0+1) /\
          canonical_fors_catalog table secret seed0 ht0 tree0 cat' /\
          forest_references cat' (behead st0) (j0+1-2^(h0+1)) /\
          cat'.[(h0+1,j0 %/ (2^(h0+1)))] = Some (node d).
      + move=> table secret d hs hd.
        have hparts := hp (node d) _ _ _ _ _ _; try by smt().
      have hinput : seed{hr} ++ address 0 ht{hr} 3 tree{hr} 0
          (height{hr}+1) (j{hr} %/ (2^(height{hr}+1))) ++
          pad (head ([],0) stack{hr}).`1 ++ pad current{hr} =
          fors_pair seed0 ht0 tree0 (h0+1) (j0 %/ (2^(h0+1)))
            (head ([],0) st0).`1 cur0.
      + rewrite /fors_pair; smt().
      have hcinput := canonical_fors_merge_member Independent.rawhistory{hr}
        Independent.secrethistory{hr} seed0 ht0 tree0 cat0 st0 cur0 h0 (j0+1).
      smt(size_behead size_ge0 size_eq0).
    seq 2 : (seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
      0<=j<2048 /\ size stack<=j /\ increasing_stack (map snd stack) /\
      stack_mass (map snd stack)=j /\ catalog_exact catalog j /\
      canonical_fors_catalog Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 catalog /\
      forest_references catalog stack j /\
      canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries /\
      current=node d /\ Independent.secrethistory.[fors_private_key ht0 tree0 j]=Some d).
    - exists* catalog,j; elim* => cat0 j0.
      wp; call (fors_records_canonical_fors seed0 ht0 tree0 cat0 base (fors_tail ht0 tree0 j0)).
      auto; rewrite /fors_private_key; smt().
    exists* catalog,d,j; elim* => cat0 sd0 j0.
    wp; call (hash_records_canonical_fors seed0 ht0 tree0 cat0 base
      (fors_leaf_input seed0 ht0 tree0 j0 (node sd0))).
    auto; rewrite expr0 ?divz1.
    move=> &hr hi; split.
    - have hi' : fors_address_valid ht0 tree0 j0 by rewrite /fors_address_valid; smt().
      have hc := canonical_fors_leaf_member Independent.rawhistory{hr}
        Independent.secrethistory{hr} seed0 ht0 tree0 j0 sd0 hi' _; first smt().
      rewrite /fors_leaf_input in hc; smt().
    move=> _ value queries table hs; split.
    - have hf := catalog_leaf_fresh cat0 j0 _; first by smt().
      have hp := catalog_partial_leaf cat0 j0 (node value).
      have hsound := catalog_sound_leaf table (fors_pair seed0 ht0 tree0)
        cat0 j0 (node value) _ hf _; first 2 by move: hs; rewrite /canonical_fors_catalog; smt().
      have hforest := forest_leaf_insert cat0 stack{hr} j0 (node value) hf _; first smt().
      have horigin := secret_leaf_insert table Independent.secrethistory{hr}
        (fors_leaf_input seed0 ht0 tree0) (fors_private_key ht0 tree0) cat0 j0 sd0 value _ _ _;
        first 3 by move: hs hi; rewrite /canonical_fors_catalog; smt().
      rewrite /canonical_fors_catalog; smt(carry_initial).
    move=> queries' table' cat cur h st hx hin.
    have ha : active_stack (map snd st) h by smt().
    have hmass : stack_mass (map snd st)+2^h=j0+1 by smt().
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    have hf := projected_catalog_finish st [] h (j0+1) cat ha _ hmass _.
    + smt().
    + smt().
    have hd := active_stack_alignment (map snd st) h (j0+1) ha hmass.
    move: hp; rewrite /=; smt().
  auto; rewrite /canonical_fors_catalog; smt(catalog_exact_empty catalog_sound_empty secret_leaf_empty).
qed.

lemma fors_witness_canonical_queries seed0 ht0 tree0 base :
  hoare [ForsBuildWitness(PreparationView(Independent)).tree :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  conseq (fors_catalog_projection (PreparationView(Independent)))
    (fors_catalog_canonical_queries seed0 ht0 tree0 base).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma raw_fors_tree_canonical_queries seed0 ht0 tree0 base :
  hoare [RawFors(PreparationView(Independent)).tree :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  conseq (fors_tree_witness_projection (PreparationView(Independent)))
    (fors_witness_canonical_queries seed0 ht0 tree0 base).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma raw_fors_root_canonical_queries seed0 ht0 tree0 base :
  hoare [RawFors(PreparationView(Independent)).root :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof. proc; call (raw_fors_tree_canonical_queries seed0 ht0 tree0 base); auto. qed.

lemma raw_fors_sign_canonical_queries seed0 ht0 tree0 base :
  hoare [RawFors(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  proc; wp; call (raw_fors_tree_canonical_queries seed0 ht0 tree0 base); wp.
  inline PreparationView(Independent).fors; wp.
  call (derive_preserves_current_fors_log seed0 base); auto.
qed.
