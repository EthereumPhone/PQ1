require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import LeafCommitmentHybrid LeafCommitmentBound LeafOpeningBound TargetOracleSplit TargetPrivateBound.
require import LeafCandidateCount LeafCandidateMass.
import RealOrder.
require import LeafCandidateBound.

lemma checked (A <: LeafCommitmentContext {-Independent}) q n &m :
  0<=q => 0<=n =>
  hoare [A(Independent).run : Independent.queries=[] /\ (glob A)=(glob A){m} ==>
    leaf_variable_count Independent.queries<=q+1 /\ size res<=n] =>
  Pr[IndependentLeafGuess(A).run() @ &m : res] <= (q+2+n)%r*(1%r/2%r)^128.
proof.
  move=> hq hn hb; exact (independent_leaf_candidate_at_state A q n &m hq hn hb).
qed.
