(* Total replay with the stop-range obligation retained in the procedure precondition. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen WotsChainSplit ChainReferenceEntries.
require import ChainValueView RawChainCached RawChainCachedProbability.

lemma concrete_chain_replay_total seed0 layer0 tree0 kp0 i0 stop0 h0 s0 :
  phoare [ConcreteChain(Independent).value :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=i0 /\ stop=stop0 /\
    0<=stop0<=7 /\ Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    chain_reference h0 s0 seed0 layer0 tree0 kp0 i0 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    res=wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 stop0] = 1%r.
proof.
  case (0<=stop0<=7)=> hs.
  + conseq (concrete_chain_replay_sure seed0 layer0 tree0 kp0 i0 stop0 h0 s0 hs); smt().
  exfalso; smt().
qed.
