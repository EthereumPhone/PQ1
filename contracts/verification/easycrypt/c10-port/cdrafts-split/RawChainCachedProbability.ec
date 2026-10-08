(* Deterministic cache replay is also a total, probability-one computation. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen WotsChainSplit ChainReferenceEntries.
require import ChainValueView RawChainCached.

lemma concrete_chain_replay_sure seed0 layer0 tree0 kp0 i0 stop0 h0 s0 :
  0<=stop0<=7 =>
  phoare [ConcreteChain(Independent).value :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=i0 /\ stop=stop0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    chain_reference h0 s0 seed0 layer0 tree0 kp0 i0 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    res=wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 stop0] = 1%r.
proof.
  move=> hstop;
  conseq (concrete_chain_value_lossless Independent independent_hash_ll independent_derive_ll)
    (concrete_chain_tables_replay seed0 layer0 tree0 kp0 i0 stop0 h0 s0 hstop); smt().
qed.
