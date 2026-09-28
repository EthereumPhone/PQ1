(* Retained reference chains replay unchanged after arbitrary table extension. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind MonotoneHistory LinearChain RawChainTrace RawChainReplay ChainHistory.

lemma derive_from_history key sd s0 h0 :
  hoare [Independent.derive :
    tail=key /\ s0.[key]=Some sd /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=sd /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. proc; if; auto; rewrite /extends; smt(domE). qed.

lemma wots_from_history tail0 sd s0 h0 :
  hoare [PreparationView(Independent).wots :
    tail=tail0 /\ s0.[wots_tag ++ tail0]=Some sd /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=sd /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. proc; call (derive_from_history (wots_tag++tail0) sd s0 h0); auto. qed.

lemma fixed_chain_replay seed0 layer0 tree0 kp0 index0 initial start0 stop0 h0 s0 :
  linear_recorded h0 (chain_input seed0 layer0 tree0 kp0 index0) initial (range start0 stop0) =>
  hoare [RawWots(PreparationView(Independent)).chain :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=index0 /\
    current=initial /\ start=start0 /\ stop=stop0 /\ start0<=stop0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=linear_value h0 (chain_input seed0 layer0 tree0 kp0 index0) initial (range start0 stop0) /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  move=> hr.
  conseq (raw_chain_replay seed0 layer0 tree0 kp0 index0 initial start0 stop0
    (linear_value h0 (chain_input seed0 layer0 tree0 kp0 index0) initial (range start0 stop0)))
    (raw_chain_extends s0 h0); smt(linear_recorded_extends).
qed.
