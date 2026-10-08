(* Every newly opened proper cut is justified by the actual returned WOTS counter. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle.
require import AcceptedContexts PersistentGrind RawCountRecorded WotsFirstCount.
require import ChainValueView ChainStageSampling CachedChainOracle ObservedValueOpening ObservedHistory.

op opened_wots_count h seed layer tree kp message counter index cut =
  exists d, first_wots_count h seed layer tree kp message counter d /\ digit 3 d index<=cut.
lemma opened_wots_count_extends h h' seed layer tree kp message counter index cut :
  extends h h' => opened_wots_count h seed layer tree kp message counter index cut =>
  opened_wots_count h' seed layer tree kp message counter index cut.
proof. rewrite /opened_wots_count; smt(first_wots_count_extends). qed.

lemma observed_wots_opening seed0 layer0 tree0 kp0 message0 opened0 :
  hoare[ChainWots(ObservedChain(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 kp0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainRevelation.opened=opened0 ==>
    ChainRevelation.opened => opened0 \/
      (res<>None /\ (layer0,tree0,kp0)=(ChainStage.layer,ChainStage.tree,ChainStage.kp) /\
       opened_wots_count Independent.rawhistory seed0 layer0 tree0 kp0 message0 (oget res).`2
         ChainStage.index ChainCut.cut)].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 kp0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainRevelation.opened=opened0 /\
    (accepted<>None => first_wots_count Independent.rawhistory seed0 layer0 tree0 kp0 message0
      (oget accepted).`1 (oget accepted).`2)).
  + call (observed_count_first seed0 layer0 tree0 kp0 message0); auto.
  sp 1; if; last by auto; smt().
  exists* accepted,Independent.rawhistory,Independent.secrethistory; elim* => acc h0 s0.
  wp; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    accepted=acc /\ acc<>None /\ 0<=step<=43 /\ perm_eq order (range 0 43) /\
    first_wots_count h0 seed0 layer0 tree0 kp0 message0 (oget acc).`1 (oget acc).`2 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 kp0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    (ChainRevelation.opened => opened0 \/
      ((layer0,tree0,kp0)=(ChainStage.layer,ChainStage.tree,ChainStage.kp) /\
       digit 3 (oget acc).`2 ChainStage.index<=ChainCut.cut))).
  + exists* order,step,ChainRevelation.opened; elim* => ord st opened.
    wp; call (observed_value_history_opening seed0 layer0 tree0 kp0 (nth 0 ord st)
      (digit 3 (oget acc).`2 (nth 0 ord st)) opened s0 h0).
    auto; rewrite /valid_chain_address;
      smt(raw_digit_bounds perm_eq_size size_range mem_nth perm_eq_mem mem_range).
  wp; call (observed_shuffle_recorded 43 s0 h0).
  auto; rewrite /opened_wots_count; smt(extends_refl first_wots_count_extends).
qed.
