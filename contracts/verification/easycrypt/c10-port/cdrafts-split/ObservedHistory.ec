(* Passive disclosure observation preserves every previously recorded oracle answer. *)
require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle.
require import AcceptedContexts PersistentGrind MonotoneHistory RawShufflePermutation PreparationHistory RawCountRecorded WotsFirstCount.
require import ChainValueView ChainStageSampling CachedChainOracle ObservedValueOpening.

lemma observed_derive_extends s0 h0 :
  hoare[ChainObservedPrefix(Independent).derive :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. proc; call (independent_derive_extends s0 h0); auto. qed.

lemma concrete_independent_extends s0 h0 :
  hoare[ConcreteChain(Independent).value :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; inline RawWots(PreparationView(Independent)).chain.
  wp; while (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + wp; call (independent_hash_extends s0 h0); auto.
  wp; inline PreparationView(Independent).wots.
  wp; call (independent_derive_extends s0 h0); auto.
qed.

lemma concrete_observed_extends s0 h0 :
  hoare[ConcreteChain(ChainObservedPrefix(Independent)).value :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; inline RawWots(PreparationView(ChainObservedPrefix(Independent))).chain.
  wp; while (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + wp; call (independent_hash_extends s0 h0); auto.
  wp; inline PreparationView(ChainObservedPrefix(Independent)).wots.
  wp; call (observed_derive_extends s0 h0); auto.
qed.

lemma observed_value_extends s0 h0 :
  hoare[ObservedChain(Independent).value :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; if.
  + call (concrete_independent_extends s0 h0); auto.
  call (concrete_observed_extends s0 h0); auto.
qed.
lemma observed_value_history_opening seed0 layer0 tree0 kp0 index0 stop0 opened0 s0 h0 :
  hoare[ObservedChain(Independent).value :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=index0 /\ stop=stop0 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 kp0 index0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    0<=stop0<=7 /\ ChainRevelation.opened=opened0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    ChainRevelation.opened=(opened0 \/
      ((layer0,tree0,kp0,index0)=(ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index) /\
       stop0<=ChainCut.cut))].
proof.
  conseq (observed_value_opening seed0 layer0 tree0 kp0 index0 stop0 opened0)
    (observed_value_extends s0 h0); smt().
qed.

lemma observed_shuffle_extends s0 h0 :
  hoare [RawShuffle(PreparationView(ChainPrefix(ObservedChain(Independent)))).permutation :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; sp 1; if; last by auto.
  while (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory); first by auto.
  wp; while (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + wp; call (independent_hash_extends s0 h0); auto.
  auto.
qed.

lemma observed_shuffle_recorded n0 s0 h0 :
  hoare [RawShuffle(PreparationView(ChainPrefix(ObservedChain(Independent)))).permutation :
    n=n0 /\ 0<=n0 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    perm_eq res (range 0 n0) /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  conseq (raw_shuffle_permutation (PreparationView(ChainPrefix(ObservedChain(Independent)))) n0 independent_hash_ll)
    (observed_shuffle_extends s0 h0); smt().
qed.

lemma observed_count_first seed0 layer0 tree0 kp0 message0 :
  hoare [ChainWots(ObservedChain(Independent)).count :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 ==>
    res<>None => first_wots_count Independent.rawhistory seed0 layer0 tree0 kp0 message0
      (oget res).`1 (oget res).`2].
proof.
  proc; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    0<=i<=signing_budget /\
    (result=None => rejected_counts Independent.rawhistory seed0 layer0 tree0 kp0 message0 i) /\
    (result<>None => first_wots_count Independent.rawhistory seed0 layer0 tree0 kp0 message0
      (oget result).`1 (oget result).`2)).
  + exists* i,Independent.rawhistory; elim* => i0 h0; wp.
    call (hash_records_with_history (wots_count_input seed0 layer0 tree0 kp0 message0 i0) h0).
    auto; rewrite /wots_count_input /first_wots_count;
      smt(extends_refl rejected_counts_extends rejected_counts_next).
  auto; smt(rejected_counts_empty).
qed.
