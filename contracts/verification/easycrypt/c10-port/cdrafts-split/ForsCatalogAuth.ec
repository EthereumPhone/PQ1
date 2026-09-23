(* The actual Fors builder returns the catalog's target sibling path. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import DyadicStack StackProjection StackAlignment StackPowers NodeCatalog NodeCatalogDomain.
require import CatalogStack CatalogForest CatalogForestMerge ForsCatalogObserver.
require import AuthCaptureIndex AuthCaptureValue AuthCaptureSchedule AuthSlots AuthSteps AuthAdvance AuthPhase.

lemma fors_catalog_auth (O <: PreparationOracle) target0 :
  hoare [ForsCatalogObserver(O).tree : target = target0 /\ 0 <= target0 < 2048 ==>
    slots_saved res.`3 res.`2 target0 11 (captured_full 2048 target0)].
proof.
  proc; while (target = target0 /\ 0 <= target0 < 2048 /\
    0 <= j <= 2048 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = j /\ catalog_exact catalog j /\
    forest_references catalog stack j /\
    slots_saved catalog auth target0 11 (captured_full j target0)).
  + wp; while (target = target0 /\ 0 <= target0 < 2048 /\
      0 <= j < 2048 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = j+1 /\
      catalog_partial catalog (j+1) height /\
      forest_references catalog stack (j+1-2^height) /\
      catalog.[(height,j %/ (2^height))] = Some current /\
      slots_saved catalog auth target0 11 (pair_captured (j+1) height target0)).
    - wp; call (_ : true ==> true); first by trivial.
      auto; move=> &hr hi.
      have hz : 0 <= height{hr} by move: hi; rewrite /active_stack; smt().
      have hstep : forall value,
        let cat' = catalog{hr}.[(height{hr}+1,j{hr} %/ (2^(height{hr}+1))) <- value] in
        let auths = fors_slots_step auth{hr} target0 height{hr}
          (j{hr} %/ (2^(height{hr}+1))) (head ([],0) stack{hr}).`1 current{hr} in
        active_stack (map snd (behead stack{hr})) (height{hr}+1) /\
        stack_mass (map snd (behead stack{hr})) + 2^(height{hr}+1) = j{hr}+1 /\
        catalog_partial cat' (j{hr}+1) (height{hr}+1) /\
        forest_references cat' (behead stack{hr}) (j{hr}+1-2^(height{hr}+1)) /\
        cat'.[(height{hr}+1,j{hr} %/ (2^(height{hr}+1)))] = Some value /\
        slots_saved cat' auths target0 11 (pair_captured (j{hr}+1) (height{hr}+1) target0).
      + move=> value.
        have hp := projected_catalog_pop stack{hr} [] height{hr} (j{hr}+1) catalog{hr} value.
        have hf := catalog_forest_merge catalog{hr} stack{hr} height{hr} (j{hr}+1) value.
        have he : catalog_extends catalog{hr}
          catalog{hr}.[(height{hr}+1,j{hr} %/ (2^(height{hr}+1))) <- value] by smt().
        have ha := fors_capture_advance catalog{hr}
          catalog{hr}.[(height{hr}+1,j{hr} %/ (2^(height{hr}+1))) <- value]
          stack{hr} current{hr} auth{hr} target0 height{hr} (j{hr}+1) 11.
        smt(stack_pow2_11).
      have ht : target{hr} = target0 by smt().
      rewrite ht /=.
      case (sibling_index (target0 %/ (2^height{hr})) %% 2 = 0) => heven.
      + rewrite ?heven /=.
        case (sibling_index (target0 %/ (2^height{hr})) * 2^height{hr} =
          j{hr} %/ (2^(height{hr}+1)) * 2^(height{hr}+1)) => heq.
        - rewrite ?heq /=; move=> d; have hs := hstep (node d).
          move: hs; rewrite /fors_slots_step /target_sibling /=; smt().
        rewrite ?heq /=; move=> d; have hs := hstep (node d).
        move: hs; rewrite /fors_slots_step /target_sibling /=; smt().
      rewrite ?heven /=.
      case (sibling_index (target0 %/ (2^height{hr})) * 2^height{hr} =
        j{hr} %/ (2^(height{hr}+1)) * 2^(height{hr}+1) + 2^height{hr}) => heq.
      + rewrite ?heq /=; move=> d; have hs := hstep (node d).
        move: hs; rewrite /fors_slots_step /target_sibling /=; smt().
      rewrite ?heq /=; move=> d; have hs := hstep (node d).
      move: hs; rewrite /fors_slots_step /target_sibling /=; smt().
    wp; call (_ : true ==> true); first by trivial.
    wp; call (_ : true ==> true); first by trivial.
    auto; rewrite !expr0 ?divz1.
    move=> &hr hi value; split.
    - have hf := catalog_leaf_fresh catalog{hr} j{hr} _; first by smt().
      have he := catalog_extension_fresh catalog{hr} (0,j{hr}) (node value) hf.
      have hp := catalog_partial_leaf catalog{hr} j{hr} (node value).
      have hr := forest_leaf_insert catalog{hr} stack{hr} j{hr} (node value) hf.
      have hs := saved_phase_start catalog{hr} catalog{hr}.[(0,j{hr}) <- node value]
        auth{hr} target0 11 j{hr} he.
      smt(carry_initial).
    move=> auth' cat cur h st hx hin.
    have ha : active_stack (map snd st) h by smt().
    have hmass : stack_mass (map snd st) + 2^h = j{hr}+1 by smt().
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    have hf := projected_catalog_finish st [] h (j{hr}+1) cat ha _ hmass _.
    + smt().
    + smt().
    have hd := active_stack_alignment (map snd st) h (j{hr}+1) ha hmass.
    have hs := saved_phase_finish st cat auth' target0 11 h (j{hr}+1) ha.
    move: hp; rewrite /=; smt().
  auto; smt(catalog_exact_empty slots_initial).
qed.
