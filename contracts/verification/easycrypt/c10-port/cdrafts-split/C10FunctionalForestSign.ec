(* Complete actual shuffled forest signing. Intermediate maps are specified
   pointwise, and the final two remembered queries are explicit. *)
require import AllCore List FMap.
require import C10Bytes C10RawOracle RawKeygen RawForest KeygenPrefixes C10Representation ForestCoordinates.
require import C10CallerInputBridge C10TreeCallerBridge C10OuterCallerBridge C10ShuffleBridge.
require import C10FixedBackend C10FixedCallerBridge C10FunctionalWots C10FunctionalWotsValue.
require import C10FunctionalForsRecovery C10FunctionalBuildHistory C10FunctionalForsBuildHistory.
require import C10FunctionalBuildContracts.
require import C10FunctionalCallerState C10FunctionalCallerShuffle C10FunctionalWotsShuffle.
require import C10FunctionalForestOne C10FunctionalForestFill C10FunctionalForestValue C10FunctionalForestRecover.

op functional_forest_initial_history f h shuffle =
  let sub = functional_derived_seed f shuffle shuffle_forest_label in
  backend_history f (functional_derive_history f h shuffle shuffle_forest_label)
    (mkseq (shuffle_block_preimage sub) (functional_shuffle_steps sub)).
op functional_forest_initial_cost f shuffle =
  functional_derive_cost shuffle +
    functional_shuffle_steps (functional_derived_seed f shuffle shuffle_forest_label).
op functional_forest_sign_compression f key seed ht d =
  multi_preimage seed (address_words 0 ht 4 0 0 0 0)
    (forest_recover_roots (interpreted_backend f) seed ht (functional_forest_indices d)
      (forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d))
      (forest_sign_paths (interpreted_backend f) seed key ht (functional_forest_indices d))).
op functional_forest_sign_state f h final key seed ht d shuffle =
  exists normal built,
    functional_history_exact f (functional_forest_initial_history f h shuffle) normal
      (functional_forest_normal_queried f key seed ht d) /\
    functional_history_exact f normal built
      (functional_tree_queried (functional_fors_build_queries f key seed ht 12) 11) /\
    let q = functional_fors_leaf_query seed ht 12 0 (functional_forest_final_root f key seed ht) in
    let comp = functional_forest_sign_compression f key seed ht d in
    final = remember (remember built q (f q)) comp (f comp).

lemma fixed_functional_forest_sign f h c key0 seed0 ht0 d0 shuffle0 :
  hoare[CommonInputForest(FixedPrefix).sign :
    seed = seed0 /\ ht = ht0 /\ digest = d0 /\ shuffle = shuffle0 /\ 0 <= ht0 < 2^32 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = forest_sign_value (interpreted_backend f) seed0 key0 ht0 (functional_forest_indices d0) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+functional_forest_initial_cost f shuffle0+80017 /\
    functional_forest_sign_state f h FixedBackend.history key0 seed0 ht0 d0 shuffle0].
proof.
  proc; seq 5 : (seed = seed0 /\ ht = ht0 /\ digest = d0 /\ shuffle = shuffle0 /\
    0 <= ht0 < 2^32 /\ backend_width f /\
    secrets = nseq 13 (nseq 16 0) /\ auths = nseq 12 (nseq 11 (nseq 16 0)) /\ roots = nseq 13 (nseq 16 0) /\
    order = functional_forest_order f (functional_derived_seed f shuffle0 shuffle_forest_label) /\
    perm_eq order (range 0 12) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_forest_initial_history f h shuffle0 /\
    FixedBackend.calls = c+functional_forest_initial_cost f shuffle0).
  + call (fixed_functional_forest_shuffle f (functional_derive_history f h shuffle0 shuffle_forest_label)
      (c+functional_derive_cost shuffle0) key0 (functional_derived_seed f shuffle0 shuffle_forest_label)).
    call (fixed_functional_derive f h c key0 shuffle0 shuffle_forest_label).
    auto; rewrite /functional_forest_initial_history /functional_forest_initial_cost; smt().
  seq 2 : (seed = seed0 /\ ht = ht0 /\ digest = d0 /\ shuffle = shuffle0 /\
    0 <= ht0 < 2^32 /\ backend_width f /\ perm_eq order (range 0 12) /\
    forest_covered (nseq 16 0) 13 secrets (fun t => functional_forest_one_secret f key0 ht0 t (forest_index d0 t)) order 12 /\
    auths = forest_sign_paths (interpreted_backend f) seed0 key0 ht0 (functional_forest_indices d0) /\
    forest_covered (nseq 16 0) 13 roots (fun t => functional_forest_one_root f key0 seed0 ht0 t (forest_index d0 t)) order 12 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+functional_forest_initial_cost f shuffle0+73872 /\
    functional_history_exact f (functional_forest_initial_history f h shuffle0) FixedBackend.history
      (functional_forest_normal_queried f key0 seed0 ht0 d0)).
  + while (seed = seed0 /\ ht = ht0 /\ digest = d0 /\ shuffle = shuffle0 /\
      0 <= ht0 < 2^32 /\ backend_width f /\ perm_eq order (range 0 12) /\ 0 <= step <= 12 /\
      forest_covered (nseq 16 0) 13 secrets (fun t => functional_forest_one_secret f key0 ht0 t (forest_index d0 t)) order step /\
      forest_covered (nseq 11 (nseq 16 0)) 12 auths (fun t => functional_forest_one_path f key0 seed0 ht0 t (forest_index d0 t)) order step /\
      forest_covered (nseq 16 0) 13 roots (fun t => functional_forest_one_root f key0 seed0 ht0 t (forest_index d0 t)) order step /\
      FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
      FixedBackend.calls = c+functional_forest_initial_cost f shuffle0+6156*step /\
      functional_history_exact f (functional_forest_initial_history f h shuffle0) FixedBackend.history
        (functional_forest_visited f key0 seed0 ht0 d0 order step)).
    - exists* step, order, FixedBackend.history; elim* => step0 order0 history0; wp.
      call (fixed_functional_forest_one f history0 (c+functional_forest_initial_cost f shuffle0+6156*step0)
        key0 seed0 ht0 (nth 0 order0 step0) (forest_index d0 (nth 0 order0 step0))).
      auto => />; rewrite /fors_fields.
      move=> &hr hh0 hh hw hp hs0 hs hss hsv has hav hrs hrv hc he hlt.
      have hn : 0 <= step0 < 12 by smt().
      have hi := outer_shuffle_index order0 step0 12 hp hn.
      have hd := forest_index_range d0 (nth 0 order0 step0).
      have hlen : size order0 = 12 by smt(perm_eq_size size_range).
      have hcs := forest_covered_next (nseq 16 0) 13 secrets{hr}
        (fun t => functional_forest_one_secret f key0 ht0 t (forest_index d0 t)) order0 step0 _ hp hn _.
      + smt().
      + rewrite /forest_covered; smt().
      have hca := forest_covered_next (nseq 11 (nseq 16 0)) 12 auths{hr}
        (fun t => functional_forest_one_path f key0 seed0 ht0 t (forest_index d0 t)) order0 step0 _ hp hn _.
      + smt().
      + rewrite /forest_covered; smt().
      have hcr := forest_covered_next (nseq 16 0) 13 roots{hr}
        (fun t => functional_forest_one_root f key0 seed0 ht0 t (forest_index d0 t)) order0 step0 _ hp hn _.
      + smt().
      + rewrite /forest_covered; smt().
      move: hcs hca hcr; rewrite /forest_covered => hcs hca hcr.
      split; first smt(caller_u32_size).
      move=> _ _ _ _ _ _ history hc' he'.
      have hhist := functional_forest_history_step f (functional_forest_initial_history f h shuffle0)
        history0 history key0 seed0 ht0 d0 order0 step0 _ he he'; first smt().
      smt().
    auto; move=> &hr hpre; split.
    - smt(forest_covered_zero functional_forest_history_initial).
    move=> calls history auths0 roots0 secrets0 step0 hstop hinv.
    have hstep : step0 = 12 by smt().
    subst step0.
    have hp : perm_eq order{hr} (range 0 12) by smt().
    have hpaths : forest_covered (nseq 11 (nseq 16 0)) 12 auths0
      (fun t => functional_forest_one_path f key0 seed0 ht0 t (forest_index d0 t)) order{hr} 12 by smt().
    have hpath_value := forest_covered_complete (nseq 11 (nseq 16 0)) auths0
      (fun t => functional_forest_one_path f key0 seed0 ht0 t (forest_index d0 t)) order{hr} hp hpaths.
    have hhist := functional_forest_history_complete f (functional_forest_initial_history f h shuffle0)
      history key0 seed0 ht0 d0 order{hr} hp _; first smt().
    rewrite (functional_forest_paths_value f key0 seed0 ht0 d0); smt().
  exists* FixedBackend.history; elim* => normal0.
  seq 1 : (seed = seed0 /\ ht = ht0 /\ digest = d0 /\ 0 <= ht0 < 2^32 /\ backend_width f /\
    perm_eq order (range 0 12) /\
    forest_covered (nseq 16 0) 13 secrets (fun t => functional_forest_one_secret f key0 ht0 t (forest_index d0 t)) order 12 /\
    auths = forest_sign_paths (interpreted_backend f) seed0 key0 ht0 (functional_forest_indices d0) /\
    forest_covered (nseq 16 0) 13 roots (fun t => functional_forest_one_root f key0 seed0 ht0 t (forest_index d0 t)) order 12 /\
    last = functional_forest_final_root f key0 seed0 ht0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+functional_forest_initial_cost f shuffle0+80015 /\
    functional_history_exact f (functional_forest_initial_history f h shuffle0) normal0
      (functional_forest_normal_queried f key0 seed0 ht0 d0) /\
    functional_history_exact f normal0 FixedBackend.history
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 12) 11)).
  + call (common_functional_fors_root f normal0 (c+functional_forest_initial_cost f shuffle0+73872) key0 seed0 ht0 12).
    auto; rewrite /fors_fields /functional_forest_final_root; smt(caller_u32_size).
  exists* FixedBackend.history; elim* => built0.
  call (fixed_hash f
    (remember built0 (functional_fors_leaf_query seed0 ht0 12 0 (functional_forest_final_root f key0 seed0 ht0))
      (f (functional_fors_leaf_query seed0 ht0 12 0 (functional_forest_final_root f key0 seed0 ht0))))
    (functional_forest_sign_compression f key0 seed0 ht0 d0) (c+functional_forest_initial_cost f shuffle0+80016)).
  wp; call (fixed_hash f built0
    (functional_fors_leaf_query seed0 ht0 12 0 (functional_forest_final_root f key0 seed0 ht0))
    (c+functional_forest_initial_cost f shuffle0+80015)).
  wp; auto => />.
  move=> &hr hh0 hh hf hp hss hsv hrs hrv hc hn hb hq hc1.
  have hs := functional_forest_secrets_finish f key0 seed0 ht0 d0 secrets{hr} order{hr} hp _.
  + rewrite /forest_covered; smt().
  have hr := functional_forest_roots_finish f key0 seed0 ht0 d0 roots{hr} order{hr} hf hp _.
  + rewrite /forest_covered; smt().
  split.
  + rewrite hr /functional_forest_sign_compression; trivial.
  move=> _ hc2; split.
  + rewrite hs /functional_forest_sign_compression.
    exact (functional_forest_result_value f key0 seed0 ht0 d0 hf).
  rewrite /functional_forest_sign_state; exists normal0 built0; smt().
qed.

lemma raw_functional_forest_sign f h c key0 seed0 ht0 d0 shuffle0 :
  equiv[RawForest(PreparationView(FixedPrefix)).sign ~ CommonInputForest(FixedPrefix).sign :
    ={seed,ht,digest,shuffle,glob FixedPrefix} /\
    seed{1} = seed0 /\ ht{1} = ht0 /\ digest{1} = d0 /\ shuffle{1} = shuffle0 /\
    0 <= ht0 < 2^32 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = forest_sign_value (interpreted_backend f) seed0 key0 ht0 (functional_forest_indices d0) /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+functional_forest_initial_cost f shuffle0+80017 /\
    functional_forest_sign_state f h FixedBackend.history{1} key0 seed0 ht0 d0 shuffle0].
proof.
  conseq (caller_forest_sign FixedPrefix) (_ : true ==> true)
    (fixed_functional_forest_sign f h c key0 seed0 ht0 d0 shuffle0) => //; smt().
qed.

lemma fixed_functional_forest_one_lossless : islossless CommonInputForest(FixedPrefix).one.
proof.
  proc; call common_functional_fors_recover_lossless;
    call common_functional_fors_sign_lossless; auto.
qed.

lemma fixed_functional_forest_sign_lossless : islossless CommonInputForest(FixedPrefix).sign.
proof.
  proc; call fixed_hash_ll; wp; call fixed_hash_ll; wp;
    call common_functional_fors_root_lossless; wp.
  while true (12-step).
  + move=> z; wp; call fixed_functional_forest_one_lossless; auto; smt().
  wp; call fixed_functional_shuffle_lossless; call fixed_functional_derive_lossless; auto; smt().
qed.

lemma raw_functional_forest_sign_lossless : islossless RawForest(PreparationView(FixedPrefix)).sign.
proof.
  apply (forest_sign_lossless (PreparationView(FixedPrefix)) fixed_hash_ll).
  proc; call fixed_derive_ll; auto.
qed.
