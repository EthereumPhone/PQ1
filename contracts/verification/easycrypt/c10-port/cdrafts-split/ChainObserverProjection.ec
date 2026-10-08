(* The disclosure flag is passive: adding it leaves the concrete oracle behavior exact. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import ChainValueView ChainStageSampling CachedChainOracle.

lemma observed_private_projection :
  equiv [Independent.derive ~ ChainObservedPrefix(Independent).derive :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof. proc; inline Independent.derive; sp; if; auto; smt(). qed.

lemma observed_concrete_projection :
  equiv [ConcreteChain(Independent).value ~ ConcreteChain(ChainObservedPrefix(Independent)).value :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; call (_ : ={glob Independent}); first by sim.
  inline PreparationView(Independent).wots PreparationView(ChainObservedPrefix(Independent)).wots.
  wp; call observed_private_projection; auto.
qed.

lemma observed_value_projection :
  equiv [ConcreteChain(Independent).value ~ ObservedChain(Independent).value :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc*; inline ObservedChain(Independent).value; wp; sp 0 6.
  if{2}.
  + wp; call (_ : ={glob Independent}); first by sim. auto.
  call observed_concrete_projection; auto.
qed.
