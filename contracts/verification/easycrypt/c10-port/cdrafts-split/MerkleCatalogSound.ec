(* Hash-table soundness of the catalog attached to the actual Merkle builder. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import RawPathReplay DyadicStack StackProjection StackAlignment NodeCatalog NodeCatalogDomain.
require import CatalogStack CatalogForest CatalogMerge CatalogOracle MerkleCatalogObserver.

lemma merkle_catalog_recorded seed0 layer0 tree0 :
  hoare [MerkleCatalogObserver(PreparationView(Independent)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 ==>
    catalog_sound Independent.rawhistory (merkle_pair seed0 layer0 tree0) res.`3 /\
    forest_references res.`3 res.`2 512].
proof.
  proc; while (seed = seed0 /\ layer = layer0 /\ tree = tree0 /\
    0 <= kp <= 512 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = kp /\ catalog_exact catalog kp /\
    catalog_sound Independent.rawhistory (merkle_pair seed0 layer0 tree0) catalog /\
    forest_references catalog stack kp).
  + wp; while (seed = seed0 /\ layer = layer0 /\ tree = tree0 /\
      0 <= kp < 512 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = kp+1 /\
      catalog_partial catalog (kp+1) height /\
      catalog_sound Independent.rawhistory (merkle_pair seed0 layer0 tree0) catalog /\
      forest_references catalog stack (kp+1-2^height) /\
      catalog.[(height,kp %/ (2^height))] = Some current).
    - exists* catalog, stack, current, height, kp;
        elim* => cat0 st0 cur0 h0 kp0.
      wp; call (hash_records_catalog (merkle_pair seed0 layer0 tree0) cat0
        (merkle_pair seed0 layer0 tree0 (h0+1) (kp0 %/ (2^(h0+1)))
          (head ([],0) st0).`1 cur0)).
      auto; move=> &hr hi.
      have hp := projected_catalog_pop st0 [] h0 (kp0+1) cat0.
      have hm : forall table d,
        catalog_sound table (merkle_pair seed0 layer0 tree0) cat0 =>
        table.[merkle_pair seed0 layer0 tree0 (h0+1) (kp0 %/ (2^(h0+1)))
          (head ([],0) st0).`1 cur0] = Some d =>
        let cat' = cat0.[(h0+1,kp0 %/ (2^(h0+1))) <- node d] in
          catalog_sound table (merkle_pair seed0 layer0 tree0) cat' /\
          forest_references cat' (behead st0) (kp0+1-2^(h0+1)) /\
          cat'.[(h0+1,kp0 %/ (2^(h0+1)))] = Some (node d).
      + move=> table d hs hd.
        apply (catalog_merge_recorded table (merkle_pair seed0 layer0 tree0)
          cat0 st0 cur0 h0 (kp0+1) d); smt().
      have hstep : forall table d,
        catalog_sound table (merkle_pair seed0 layer0 tree0) cat0 =>
        table.[merkle_pair seed0 layer0 tree0 (h0+1) (kp0 %/ (2^(h0+1)))
          (head ([],0) st0).`1 cur0] = Some d =>
        let cat' = cat0.[(h0+1,kp0 %/ (2^(h0+1))) <- node d] in
          active_stack (map snd (behead st0)) (h0+1) /\
          stack_mass (map snd (behead st0)) + 2^(h0+1) = kp0+1 /\
          catalog_partial cat' (kp0+1) (h0+1) /\
          catalog_sound table (merkle_pair seed0 layer0 tree0) cat' /\
          forest_references cat' (behead st0) (kp0+1-2^(h0+1)) /\
          cat'.[(h0+1,kp0 %/ (2^(h0+1)))] = Some (node d).
      + move=> table d hs hd.
        have hparts := hp (node d) _ _ _ _ _ _; try by smt().
      have hinput : seed{hr} ++ address layer{hr} tree{hr} 2 0 0
          (height{hr}+1) (kp{hr} %/ (2^(height{hr}+1))) ++
          pad (head ([],0) stack{hr}).`1 ++ pad current{hr} =
          merkle_pair seed0 layer0 tree0 (h0+1) (kp0 %/ (2^(h0+1)))
            (head ([],0) st0).`1 cur0.
      + rewrite /merkle_pair; smt().
      smt().
    exists* catalog; elim* => cat0.
    wp; call (leaf_keeps_catalog RawKeygen (merkle_pair seed0 layer0 tree0) cat0).
    auto; rewrite expr0 ?divz1.
    move=> &hr hi; split; first by smt().
    move=> _ value table hs; split.
    - have hf := catalog_leaf_fresh cat0 kp{hr} _; first by smt().
      have hp := catalog_partial_leaf cat0 kp{hr} value.
      have hsound := catalog_sound_leaf table (merkle_pair seed0 layer0 tree0)
        cat0 kp{hr} value hs hf _; first by smt().
      have hforest := forest_leaf_insert cat0 stack{hr} kp{hr} value hf _;
        first by smt().
      smt(carry_initial).
    move=> table' cat cur h st hx hin.
    have ha : active_stack (map snd st) h by smt().
    have hmass : stack_mass (map snd st) + 2^h = kp{hr}+1 by smt().
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    have hf := projected_catalog_finish st [] h (kp{hr}+1) cat ha _ hmass _.
    + smt().
    + smt().
    have hd := active_stack_alignment (map snd st) h (kp{hr}+1) ha hmass.
    move: hp; rewrite /=; smt().
  auto; smt(catalog_exact_empty catalog_sound_empty).
qed.
