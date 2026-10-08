(* The full adaptive chain context preserves the exact passive guess ledger. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen.
require import ChainValueView ChainStageSampling CachedChainOracle DualDigestSampling.
require import RedactedChainOracle ChainPublicHybrid ChainGuessInstrumentation.

lemma chain_context_instrumentation
  (A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRedaction,-DualDigest,
    -RedactedCachedChain,-RedactedChainPrefix,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) hidden0 :
  equiv [A(HybridCachedChain).run ~ A(RedactedCachedChain).run :
    ={glob A,glob Independent,ChainRedaction.opened,ChainCut.cut,ChainStage.seed,ChainStage.layer,
      ChainStage.tree,ChainStage.kp,ChainStage.index,ChainStage.values} /\
    DualDigest.hidden{1}=hidden0 /\ ChainGuess.bad{1}=chain_query_hit hidden0 Independent.queries{2} ==>
    ={res,glob A,glob Independent,ChainRedaction.opened,ChainCut.cut,ChainStage.seed,ChainStage.layer,
      ChainStage.tree,ChainStage.kp,ChainStage.index,ChainStage.values} /\
    ChainGuess.bad{1}=chain_query_hit hidden0 Independent.queries{2}].
proof.
  proc (={glob Independent,ChainRedaction.opened,ChainCut.cut,ChainStage.seed,ChainStage.layer,
      ChainStage.tree,ChainStage.kp,ChainStage.index,ChainStage.values} /\
    DualDigest.hidden{1}=hidden0 /\ ChainGuess.bad{1}=chain_query_hit hidden0 Independent.queries{2}) => //.
  + proc*; call (chain_hash_instrumentation hidden0); auto.
  + proc*; call (_ : ={glob Independent,ChainRedaction.opened,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index}); first by sim.
    auto.
  proc*; call (chain_value_instrumentation hidden0); auto.
qed.
