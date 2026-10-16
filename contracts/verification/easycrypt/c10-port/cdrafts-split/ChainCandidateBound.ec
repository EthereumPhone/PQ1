(* A numerical hiding kernel for a selected, unopened, fully programmed chain cut. *)
require import AllCore List Distr DList FMap StdOrder.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import ChainValueView ChainStageSampling CachedChainOracle DualDigestSampling.
require import RedactedChainOracle ChainPublicHybrid ChainHybridContext.
require import ChainVectorInstall VisibleChainInstallation ChainVisibleGuess NodeVectorMass VectorGuessBound.
import RealOrder.

require import ProgrammedChainBound ChainCandidateMass.

lemma programmed_unopened_chain_candidate_bound
  (A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,
    -ChainVectorInstall,-CachedChain,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain})
  k &m :
  (forall (O <: ChainOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.value => islossless A(O).run) =>
  0<=ChainCut.cut{m}<7 => 0<=k =>
  hoare [VisibleChainCandidates(A).run :
    (glob VisibleChainCandidates(A))=(glob VisibleChainCandidates(A)){m} ==> size (chain_variable_nodes res)<=k] =>
  Pr[ProgrammedUnopenedChainGuess(A).run() @ &m : res] <= 8%r*(k+2)%r*(1%r/2%r)^128.
proof.
  move=> hll hcut hk hb.
  have he : Pr[ProgrammedUnopenedChainGuess(A).run() @ &m : res] <=
    Pr[HybridChainVectorGuess(A).run() @ &m : res \/ ChainGuess.bad].
  + byequiv (programmed_chain_hybrid_upto A hll) => //; smt().
  have hp : Pr[HybridChainVectorGuess(A).run() @ &m : res \/ ChainGuess.bad]=
    Pr[IndependentVectorGuess(VisibleChainCandidates(A)).run() @ &m : res].
  + byequiv (visible_chain_vector_guess_projection A) => //; smt().
  have hbnd := independent_vector_candidate_bound (VisibleChainCandidates(A)) k &m hk hb.
  smt().
qed.
