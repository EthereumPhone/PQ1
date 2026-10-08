(* A numerical hiding kernel for a selected, unopened, fully programmed chain cut. *)
require import AllCore List Distr DList FMap StdOrder.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import ChainValueView ChainStageSampling CachedChainOracle DualDigestSampling.
require import RedactedChainOracle ChainPublicHybrid ChainHybridContext.
require import ChainVectorInstall VisibleChainInstallation ChainVisibleGuess NodeVectorMass VectorGuessBound.
import RealOrder.

module ProgrammedUnopenedChainGuess (A : ChainContext) = {
  proc run() : bool = {
    var outputs;
    Independent.init();
    DualDigest.hidden <$ dlist full_digest 8;
    DualDigest.visible <$ dlist full_digest 8;
    IndexedChainInstall.run();
    ChainRedaction.opened <- false;
    outputs <@ A(RedactedCachedChain).run();
    return !ChainRedaction.opened /\
      mem outputs (node (nth (nseq 256 false) DualDigest.hidden ChainCut.cut));
  }
}.
lemma programmed_chain_hybrid_upto
  (A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,
    -ChainVectorInstall,-CachedChain,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) :
  (forall (O <: ChainOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.value => islossless A(O).run) =>
  equiv [ProgrammedUnopenedChainGuess(A).run ~ HybridChainVectorGuess(A).run :
    ={glob A,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    0<=ChainCut.cut{1}<7 ==>
    res{1} => res{2} \/ ChainGuess.bad{2}].
proof.
  move=> hll; proc.
  call (adaptive_chain_hybrid A hll).
  wp; call visible_chain_installation.
  rnd; rnd; inline Independent.init; auto=> />;
    smt(supp_dlist_size node_vector_has_coordinate).
qed.
lemma programmed_unopened_chain_bound
  (A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,
    -ChainVectorInstall,-CachedChain,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain})
  k &m :
  (forall (O <: ChainOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.value => islossless A(O).run) =>
  0<=ChainCut.cut{m}<7 => 0<=k =>
  hoare [VisibleChainCandidates(A).run :
    (glob VisibleChainCandidates(A))=(glob VisibleChainCandidates(A)){m} ==> size res<=k] =>
  Pr[ProgrammedUnopenedChainGuess(A).run() @ &m : res] <= 8%r*k%r*(1%r/2%r)^128.
proof.
  move=> hll hcut hk hb.
  have he : Pr[ProgrammedUnopenedChainGuess(A).run() @ &m : res] <=
    Pr[HybridChainVectorGuess(A).run() @ &m : res \/ ChainGuess.bad].
  + byequiv (programmed_chain_hybrid_upto A hll) => //; smt().
  have hp : Pr[HybridChainVectorGuess(A).run() @ &m : res \/ ChainGuess.bad]=
    Pr[IndependentVectorGuess(VisibleChainCandidates(A)).run() @ &m : res].
  + byequiv (visible_chain_vector_guess_projection A) => //; smt().
  have hbnd := independent_vector_guess_bound (VisibleChainCandidates(A)) k &m hk hb.
  smt().
qed.
