(* The fresh memoized unopened-chain experiment has the programmed-vector law. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen.
require import ChainValueView ChainStageSampling CachedChainOracle ChainReferenceSampling ChainUnopenedEvent.
require import RedactedChainOracle DualDigestSampling ProgrammedChainBound CompleteChainProgramming.
require import PrivateValueSampling PublicTargetSampling ChainVectorInstall VisibleChainInstallation.

module FreshCachedChainGuess (A : ChainContext) = {
  proc run() : bool = {
    var result; Independent.init(); CompleteChainCache.sample();
    result <@ CachedUnopenedGuess(A).run(); return result;
  }
}.
module FreshRedactedChainGuess (A : ChainContext) = {
  proc run() : bool = {
    var result; Independent.init(); CompleteChainCache.sample();
    result <@ RedactedUnopenedGuess(A).run(); return result;
  }
}.
lemma fresh_chain_redaction
  (A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,
    -PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -CachedChain,-RedactedCachedChain,-RedactedChainPrefix}) :
  (forall (O <: ChainOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.value => islossless A(O).run) =>
  equiv[FreshCachedChainGuess(A).run ~ FreshRedactedChainGuess(A).run :
    ={glob A,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==> ={res}].
proof.
  move=> ha; proc; call (chain_unopened_event_redaction A ha).
  call (_ : ={glob Independent,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent,ChainStage.values}); first by sim.
  inline Independent.init; auto.
qed.
lemma fresh_redacted_programmed
  (A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,
    -PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainVectorInstall,-DualDigest,-CachedChain,-RedactedCachedChain,-RedactedChainPrefix}) :
  equiv[FreshRedactedChainGuess(A).run ~ ProgrammedUnopenedChainGuess(A).run :
    ={glob A,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    0<=ChainCut.cut{1}<7 ==> ={res}].
proof.
  proc; inline RedactedUnopenedGuess(A).run.
  outline{2} [2..4] by { IndexedRandomChain.sample(); }.
  wp; call (_ : ={glob Independent,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,
    ChainStage.values,ChainCut.cut,ChainRedaction.opened}); 1,2,3: by sim.
  wp; call (_ : ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty /\ 0<=ChainCut.cut{1}<7 ==>
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,
      ChainStage.current,ChainStage.step,ChainStage.values} /\
    nth (nseq 16 0) ChainStage.values{1} ChainCut.cut{1}=
      node(nth (nseq 256 false) DualDigest.hidden{2} ChainCut.cut{2})).
  + conseq complete_chain_indexed_projection _ indexed_random_chain_cut; smt().
  inline Independent.init; auto; smt().
qed.
