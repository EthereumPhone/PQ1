(* The actual Merkle builder returns the catalog's target sibling path. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import DyadicStack StackProjection StackAlignment StackPowers NodeCatalog NodeCatalogDomain.
require import CatalogStack CatalogForest CatalogForestMerge MerkleCatalogObserver.
require import AuthCaptureIndex AuthCaptureValue AuthCaptureSchedule AuthSlots AuthSteps AuthAdvance AuthPhase.

lemma merkle_catalog_auth (O <: PreparationOracle) target0 :
  hoare [MerkleCatalogObserver(O).build : target = target0 /\ 0 <= target0 < 512 ==>
    slots_saved res.`3 res.`1 target0 9 (captured_full 512 target0)].
proof.
  proc; while (target = target0 /\ 0 <= target0 < 512 /\
    0 <= kp <= 512 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = kp /\ catalog_exact catalog kp /\
    forest_references catalog stack kp /\
    slots_saved catalog keep target0 9 (captured_full kp target0) /\
    slots_flags kept 9 (captured_full kp target0)).
  + wp; while (target = target0 /\ 0 <= target0 < 512 /\
      0 <= kp < 512 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = kp+1 /\
      catalog_partial catalog (kp+1) height /\
      forest_references catalog stack (kp+1-2^height) /\
      catalog.[(height,kp %/ (2^height))] = Some current /\
      slots_saved catalog keep target0 9 (pair_captured (kp+1) height target0) /\
      slots_flags kept 9 (pair_captured (kp+1) height target0)).
    - wp; call (_ : true ==> true); first by trivial.
      auto; move=> &hr hi.
      have hz : 0 <= height{hr} by move: hi; rewrite /active_stack; smt().
      have hleft := merkle_left_index kp{hr} height{hr} hz.
      have hstep : forall value,
        let cat' = catalog{hr}.[(height{hr}+1,kp{hr} %/ (2^(height{hr}+1))) <- value] in
        let arrays = merkle_slots_step keep{hr} kept{hr} target0 height{hr}
          (kp{hr} %/ (2^(height{hr}+1))) (head ([],0) stack{hr}).`1 current{hr} in
        active_stack (map snd (behead stack{hr})) (height{hr}+1) /\
        stack_mass (map snd (behead stack{hr})) + 2^(height{hr}+1) = kp{hr}+1 /\
        catalog_partial cat' (kp{hr}+1) (height{hr}+1) /\
        forest_references cat' (behead stack{hr}) (kp{hr}+1-2^(height{hr}+1)) /\
        cat'.[(height{hr}+1,kp{hr} %/ (2^(height{hr}+1)))] = Some value /\
        slots_saved cat' arrays.`1 target0 9 (pair_captured (kp{hr}+1) (height{hr}+1) target0) /\
        slots_flags arrays.`2 9 (pair_captured (kp{hr}+1) (height{hr}+1) target0).
      + move=> value.
        have hp := projected_catalog_pop stack{hr} [] height{hr} (kp{hr}+1) catalog{hr} value.
        have hf := catalog_forest_merge catalog{hr} stack{hr} height{hr} (kp{hr}+1) value.
        have he : catalog_extends catalog{hr}
          catalog{hr}.[(height{hr}+1,kp{hr} %/ (2^(height{hr}+1))) <- value] by smt().
        have ha := merkle_capture_advance catalog{hr}
          catalog{hr}.[(height{hr}+1,kp{hr} %/ (2^(height{hr}+1))) <- value]
          stack{hr} current{hr} keep{hr} kept{hr} target0 height{hr} (kp{hr}+1) 9.
        smt(stack_pow2_9).
      have ht : target{hr} = target0 by smt().
      rewrite ht hleft.
      case (nth false kept{hr} height{hr}) => hk.
      + rewrite ?hk /=; move=> d; have hs := hstep (node d).
        move: hs; rewrite /merkle_slots_step hk /=; smt().
      rewrite ?hk /=.
      case (2*(kp{hr} %/ (2^(height{hr}+1))) = sibling_index (target0 %/ (2^height{hr}))) => hl.
      + rewrite ?hl /=; move=> d; have hs := hstep (node d).
        move: hs; rewrite /merkle_slots_step /target_sibling hk hl /=; smt().
      rewrite ?hl /=.
      case (2*(kp{hr} %/ (2^(height{hr}+1)))+1 = sibling_index (target0 %/ (2^height{hr}))) => hr.
      + rewrite ?hr /=; move=> d; have hs := hstep (node d).
        move: hs; rewrite /merkle_slots_step /target_sibling hk hl hr /=; smt().
      rewrite ?hr /=; move=> d; have hs := hstep (node d).
      move: hs; rewrite /merkle_slots_step /target_sibling hk hl hr /=; smt().
    wp; call (_ : true ==> true); first by trivial.
    auto; rewrite !expr0 ?divz1.
    move=> &hr hi value; split.
    - have hf := catalog_leaf_fresh catalog{hr} kp{hr} _; first by smt().
      have he := catalog_extension_fresh catalog{hr} (0,kp{hr}) value hf.
      have hp := catalog_partial_leaf catalog{hr} kp{hr} value.
      have hr := forest_leaf_insert catalog{hr} stack{hr} kp{hr} value hf.
      have hs := slots_phase_start catalog{hr} catalog{hr}.[(0,kp{hr}) <- value]
        keep{hr} kept{hr} target0 9 kp{hr} he.
      smt(carry_initial).
    move=> cat cur h keep' kept' st hx hin.
    have ha : active_stack (map snd st) h by smt().
    have hmass : stack_mass (map snd st) + 2^h = kp{hr}+1 by smt().
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    have hf := projected_catalog_finish st [] h (kp{hr}+1) cat ha _ hmass _.
    + smt().
    + smt().
    have hd := active_stack_alignment (map snd st) h (kp{hr}+1) ha hmass.
    have hs := slots_phase_finish st cat keep' kept' target0 9 h (kp{hr}+1) ha.
    move: hp; rewrite /=; smt().
  auto; smt(catalog_exact_empty slots_initial).
qed.
