(* Actual chain replay through a retained prefix/suffix split. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import LinearChain LinearSplit RawChainTrace ChainHistory.

lemma raw_chain_replay seed0 layer0 tree0 kp0 index0 initial start0 stop0 expected :
  hoare [RawWots(PreparationView(Independent)).chain :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=index0 /\
    current=initial /\ start=start0 /\ stop=stop0 /\ start0<=stop0 /\
    linear_recorded Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 stop0) /\
    linear_value Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 stop0) = expected ==>
    res=expected /\
    linear_recorded Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 stop0)].
proof.
  conseq (raw_chain_recorded seed0 layer0 tree0 kp0 index0 initial start0 stop0)
    (raw_chain_keeps_linear (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 stop0) expected); smt().
qed.
