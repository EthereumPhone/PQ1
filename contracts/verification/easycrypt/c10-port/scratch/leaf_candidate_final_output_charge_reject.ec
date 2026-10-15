require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import LeafCommitmentHybrid LeafCommitmentBound LeafOpeningBound TargetOracleSplit TargetPrivateBound.
require import LeafCandidateCount LeafCandidateMass.
import RealOrder.
require import LeafCandidateBound.

lemma checked (A <: LeafOpeningContext {-LeafCommitmentReal,-LeafCommitmentHybrid,-Shared,-Independent,
    -RealLeafOpening,-RedactedLeafState}) q n &m :
  (forall (O <: LeafOpeningOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.reveal => islossless A(O).run) =>
  0<=q => 0<=n =>
  hoare [A(RedactedLeafOpening(Independent)).run :
    Independent.queries=[] /\ !RedactedLeafState.revealed /\ (glob A)=(glob A){m} ==>
    leaf_variable_count Independent.queries<=q /\ size res<=n] =>
  Pr[RealUnopenedLeafGuess(A).run() @ &m : res] <= (q+2)%r*(1%r/2%r)^128.
proof.
  move=> ha hq hn hb; exact (adaptive_unopened_leaf_candidate_at_state A q n &m ha hq hn hb).
qed.
