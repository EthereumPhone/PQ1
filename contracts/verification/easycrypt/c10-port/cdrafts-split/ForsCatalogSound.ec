(* Hash-table soundness of the catalog attached to the actual FORS builder. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import RawForsPathReplay DyadicStack StackProjection StackAlignment NodeCatalog NodeCatalogDomain.
require import CatalogStack CatalogForest CatalogMerge CatalogOracle ForsCatalogObserver.

lemma fors_catalog_recorded seed0 ht0 tree0 :
  hoare [ForsCatalogObserver(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 ==>
    catalog_sound Independent.rawhistory (fors_pair seed0 ht0 tree0) res.`3 /\
    forest_references res.`3 res.`1 2048].
proof.
  proc; while (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\
    0 <= j <= 2048 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = j /\ catalog_exact catalog j /\
    catalog_sound Independent.rawhistory (fors_pair seed0 ht0 tree0) catalog /\
    forest_references catalog stack j).
  + wp; while (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\
      0 <= j < 2048 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = j+1 /\
      catalog_partial catalog (j+1) height /\
      catalog_sound Independent.rawhistory (fors_pair seed0 ht0 tree0) catalog /\
      forest_references catalog stack (j+1-2^height) /\
      catalog.[(height,j %/ (2^height))] = Some current).
    - exists* catalog, stack, current, height, j;
        elim* => cat0 st0 cur0 h0 j0.
      wp; call (hash_records_catalog (fors_pair seed0 ht0 tree0) cat0
        (fors_pair seed0 ht0 tree0 (h0+1) (j0 %/ (2^(h0+1)))
          (head ([],0) st0).`1 cur0)).
      auto; move=> &hr hi.
      have hp := projected_catalog_pop st0 [] h0 (j0+1) cat0.
      have hm : forall table d,
        catalog_sound table (fors_pair seed0 ht0 tree0) cat0 =>
        table.[fors_pair seed0 ht0 tree0 (h0+1) (j0 %/ (2^(h0+1)))
          (head ([],0) st0).`1 cur0] = Some d =>
        let cat' = cat0.[(h0+1,j0 %/ (2^(h0+1))) <- node d] in
          catalog_sound table (fors_pair seed0 ht0 tree0) cat' /\
          forest_references cat' (behead st0) (j0+1-2^(h0+1)) /\
          cat'.[(h0+1,j0 %/ (2^(h0+1)))] = Some (node d).
      + move=> table d hs hd.
        apply (catalog_merge_recorded table (fors_pair seed0 ht0 tree0)
          cat0 st0 cur0 h0 (j0+1) d); smt().
      have hstep : forall table d,
        catalog_sound table (fors_pair seed0 ht0 tree0) cat0 =>
        table.[fors_pair seed0 ht0 tree0 (h0+1) (j0 %/ (2^(h0+1)))
          (head ([],0) st0).`1 cur0] = Some d =>
        let cat' = cat0.[(h0+1,j0 %/ (2^(h0+1))) <- node d] in
          active_stack (map snd (behead st0)) (h0+1) /\
          stack_mass (map snd (behead st0)) + 2^(h0+1) = j0+1 /\
          catalog_partial cat' (j0+1) (h0+1) /\
          catalog_sound table (fors_pair seed0 ht0 tree0) cat' /\
          forest_references cat' (behead st0) (j0+1-2^(h0+1)) /\
          cat'.[(h0+1,j0 %/ (2^(h0+1)))] = Some (node d).
      + move=> table d hs hd.
        have hparts := hp (node d) _ _ _ _ _ _; try by smt().
      have hinput : seed{hr} ++ address 0 ht{hr} 3 tree{hr} 0
          (height{hr}+1) (j{hr} %/ (2^(height{hr}+1))) ++
          pad (head ([],0) stack{hr}).`1 ++ pad current{hr} =
          fors_pair seed0 ht0 tree0 (h0+1) (j0 %/ (2^(h0+1)))
            (head ([],0) st0).`1 cur0.
      + rewrite /fors_pair; smt().
      smt().
    exists* catalog; elim* => cat0.
    wp; call (hash_keeps_catalog (fors_pair seed0 ht0 tree0) cat0).
    wp; call (fors_keeps_catalog (fors_pair seed0 ht0 tree0) cat0).
    auto; rewrite expr0 ?divz1.
    move=> &hr hi; split; first by smt().
    move=> _ _; split; first by smt().
    move=> _ value table hs; split.
    - have hf := catalog_leaf_fresh cat0 j{hr} _; first by smt().
      have hp := catalog_partial_leaf cat0 j{hr} (node value).
      have hsound := catalog_sound_leaf table (fors_pair seed0 ht0 tree0)
        cat0 j{hr} (node value) hs hf _; first by smt().
      have hforest := forest_leaf_insert cat0 stack{hr} j{hr} (node value) hf _;
        first by smt().
      smt(carry_initial).
    move=> table' cat cur h st hx hin.
    have ha : active_stack (map snd st) h by smt().
    have hmass : stack_mass (map snd st) + 2^h = j{hr}+1 by smt().
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    have hf := projected_catalog_finish st [] h (j{hr}+1) cat ha _ hmass _.
    + smt().
    + smt().
    have hd := active_stack_alignment (map snd st) h (j{hr}+1) ha hmass.
    move: hp; rewrite /=; smt().
  auto; smt(catalog_exact_empty catalog_sound_empty).
qed.
