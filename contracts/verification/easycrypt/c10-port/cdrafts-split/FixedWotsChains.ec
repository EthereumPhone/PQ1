(* Prefix and suffix executions of the real chain use the fixed keygen witness. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind LinearChain RawChainTrace RawChainReplay ChainHistory.
require import WotsReference WotsChainSplit.

lemma fixed_wots_prefix seed0 layer0 tree0 kp0 i0 cut h0 s0 :
  hoare [RawWots(PreparationView(Independent)).chain :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=i0 /\
    current=wots_start s0 layer0 tree0 kp0 i0 /\ start=0 /\ stop=cut /\
    wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\ 0<=i0<43 /\ 0<=cut<=7 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 cut /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  conseq (raw_chain_replay seed0 layer0 tree0 kp0 i0 (wots_start s0 layer0 tree0 kp0 i0) 0 cut
    (wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 cut)) (raw_chain_extends s0 h0).
  + move=> &m hp.
    have hs := wots_reference_split h0 s0 seed0 layer0 tree0 kp0 i0 cut _ _ _; first 3 smt().
    have he := linear_recorded_extends h0 Independent.rawhistory{m}
      (chain_input seed0 layer0 tree0 kp0 i0) (wots_start s0 layer0 tree0 kp0 i0) (range 0 cut) _ _;
      first 2 smt().
    rewrite /wots_partial; smt().
  smt().
qed.

lemma fixed_wots_suffix seed0 layer0 tree0 kp0 i0 cut h0 s0 :
  hoare [RawWots(PreparationView(Independent)).chain :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=i0 /\
    current=wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 cut /\ start=cut /\ stop=7 /\
    wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\ 0<=i0<43 /\ 0<=cut<=7 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=wots_endpoint h0 s0 seed0 layer0 tree0 kp0 i0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  conseq (raw_chain_replay seed0 layer0 tree0 kp0 i0
    (wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 cut) cut 7
    (wots_endpoint h0 s0 seed0 layer0 tree0 kp0 i0)) (raw_chain_extends s0 h0).
  + move=> &m hp.
    have hs := wots_reference_split h0 s0 seed0 layer0 tree0 kp0 i0 cut _ _ _; first 3 smt().
    have he := linear_recorded_extends h0 Independent.rawhistory{m}
      (chain_input seed0 layer0 tree0 kp0 i0) (wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 cut)
      (range cut 7) _ _; first 2 smt().
    smt().
  smt().
qed.
