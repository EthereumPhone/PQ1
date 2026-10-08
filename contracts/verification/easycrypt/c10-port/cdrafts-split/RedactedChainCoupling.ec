(* Cached and redacted chains agree until an opening, including concrete fallback calls. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import ChainValueView ChainStageSampling CachedChainOracle RedactedChainOracle.

lemma redacted_concrete_chain_coupling :
  equiv [ConcreteChain(ChainObservedPrefix(Independent)).value ~ ConcreteChain(RedactedChainPrefix).value :
    ={arg,glob Independent,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    !ChainRevelation.opened{1} /\ !ChainRedaction.opened{2} ==>
    if ChainRedaction.opened{2} then ChainRevelation.opened{1}
    else ={res,glob Independent} /\ !ChainRevelation.opened{1}].
proof.
  proc; seq 1 1 :
    (={seed,layer,tree,kp,index,stop} /\
      if ChainRedaction.opened{2} then ChainRevelation.opened{1}
      else ={d,glob Independent} /\ !ChainRevelation.opened{1}).
  + inline PreparationView(ChainObservedPrefix(Independent)).wots PreparationView(RedactedChainPrefix).wots.
    wp; call redacted_chain_derive_coupling; auto; smt().
  case (ChainRedaction.opened{2}).
  + call{1} (raw_chain_lossless (PreparationView(ChainObservedPrefix(Independent))) independent_hash_ll).
    call{2} (raw_chain_lossless (PreparationView(RedactedChainPrefix)) independent_hash_ll).
    auto; smt().
  call (_ : ={glob Independent}); first by sim.
  auto; smt().
qed.

lemma redacted_cached_value_coupling :
  equiv [CachedChain.value ~ RedactedCachedChain.value :
    ={arg,glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,
      ChainStage.kp,ChainStage.index,ChainStage.values} /\
    !ChainRevelation.opened{1} /\ !ChainRedaction.opened{2} ==>
    if ChainRedaction.opened{2} then ChainRevelation.opened{1}
    else ={res,glob Independent} /\ !ChainRevelation.opened{1}].
proof.
  proc; if; first auto.
  + if{2}; auto; smt().
  call redacted_concrete_chain_coupling; auto; smt().
qed.
