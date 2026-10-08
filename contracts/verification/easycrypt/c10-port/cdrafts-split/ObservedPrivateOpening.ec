(* FORS and randomizer domains cannot open the selected WOTS private derivation. *)
require import AllCore List.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest RawShuffle.
require import RoleGrind C10HashDomains C10RawGrind.
require import ChainValueView ChainStageSampling CachedChainOracle WotsInputSeparation.

lemma observed_fors_unopened opened0 :
  hoare[PreparationView(ChainPrefix(ObservedChain(Independent))).fors :
    ChainRevelation.opened=opened0 ==> ChainRevelation.opened=opened0].
proof.
  proc; inline ChainObservedPrefix(Independent).derive.
  wp; call (_ : true ==> true); first by trivial.
  auto; smt(wots_fors_input_disjoint).
qed.
lemma observed_fors_tree_unopened opened0 :
  hoare[RawFors(PreparationView(ChainPrefix(ObservedChain(Independent)))).tree :
    ChainRevelation.opened=opened0 ==> ChainRevelation.opened=opened0].
proof.
  proc; while (ChainRevelation.opened=opened0).
  + wp; while (ChainRevelation.opened=opened0).
    - wp; call (_ : true ==> true); first by trivial.
      auto.
    wp; call (_ : true ==> true); first by trivial.
    wp; call (observed_fors_unopened opened0); auto.
  auto.
qed.
lemma observed_fors_sign_unopened opened0 :
  hoare[RawFors(PreparationView(ChainPrefix(ObservedChain(Independent)))).sign :
    ChainRevelation.opened=opened0 ==> ChainRevelation.opened=opened0].
proof.
  proc; call (observed_fors_tree_unopened opened0); wp;
    call (observed_fors_unopened opened0); auto.
qed.
lemma observed_forest_one_unopened opened0 :
  hoare[RawForest(PreparationView(ChainPrefix(ObservedChain(Independent)))).one :
    ChainRevelation.opened=opened0 ==> ChainRevelation.opened=opened0].
proof.
  proc; call (_ : true ==> true); first by trivial.
  call (observed_fors_sign_unopened opened0); auto.
qed.
lemma observed_forest_unopened opened0 :
  hoare[RawForest(PreparationView(ChainPrefix(ObservedChain(Independent)))).sign :
    ChainRevelation.opened=opened0 ==> ChainRevelation.opened=opened0].
proof.
  proc; call (_ : true ==> true); first by trivial.
  wp; call (_ : true ==> true); first by trivial.
  wp; inline RawFors(PreparationView(ChainPrefix(ObservedChain(Independent)))).root.
  wp; call (observed_fors_tree_unopened opened0); wp.
  while (ChainRevelation.opened=opened0).
  + wp; call (observed_forest_one_unopened opened0); auto.
  wp; call (_ : true ==> true); first by trivial.
  call (_ : true ==> true); first by trivial.
  auto.
qed.
lemma observed_grind_unopened opened0 :
  hoare[RoleGrind(ChainPrefix(ObservedChain(Independent))).run :
    ChainRevelation.opened=opened0 ==> ChainRevelation.opened=opened0].
proof.
  proc; while (ChainRevelation.opened=opened0).
  + wp; call (_ : true ==> true); first by trivial.
    wp; inline ChainObservedPrefix(Independent).derive.
    wp; call (_ : true ==> true); first by trivial.
    auto; rewrite /r_tail; smt(wots_r_input_disjoint).
  auto.
qed.
