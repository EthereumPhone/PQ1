(* Redaction preserves the exact unopened-output event on a prepared chain. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen.
require import ChainValueView ChainStageSampling CachedChainOracle RedactedChainOracle RedactedChainContext.

module CachedUnopenedGuess (A : ChainContext) = {
  proc run() : bool = {
    var outputs;
    ChainRevelation.opened <- false;
    outputs <@ A(CachedChain).run();
    return !ChainRevelation.opened /\ mem outputs (nth (nseq 16 0) ChainStage.values ChainCut.cut);
  }
}.
module RedactedUnopenedGuess (A : ChainContext) = {
  proc run() : bool = {
    var outputs;
    ChainRedaction.opened <- false;
    outputs <@ A(RedactedCachedChain).run();
    return !ChainRedaction.opened /\ mem outputs (nth (nseq 16 0) ChainStage.values ChainCut.cut);
  }
}.
lemma chain_unopened_event_redaction
  (A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,
    -CachedChain,-RedactedCachedChain,-RedactedChainPrefix}) :
  (forall (O <: ChainOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.value => islossless A(O).run) =>
  equiv [CachedUnopenedGuess(A).run ~ RedactedUnopenedGuess(A).run :
    ={glob A,glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,
      ChainStage.kp,ChainStage.index,ChainStage.values} ==> ={res}].
proof. move=> hll; proc; call (redact_chain_context A hll); auto; smt(). qed.
