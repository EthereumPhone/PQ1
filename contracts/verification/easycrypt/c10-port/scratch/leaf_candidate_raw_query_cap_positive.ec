require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawKeygen RoleGrindCost RawSigner FullSession FullPrefix ByteSession ExposureLog ClientQueryLog.
require import LeafSessionView LeafOpeningBound TargetOracleSplit TargetByteView TargetSessionOpenings.
require import TargetAdapterCost LeafTargetSignerCost LeafBudgetKeygen LeafCandidateCount.
require import LeafTargetSessionCost.

lemma checked (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -OtherPrivate,-RedactedLeafState,-TargetConfig}) qr qs :
  0<=qr => 0<=qs =>
  hoare [TargetByteCandidates(A,IdealTarget).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\ Independent.queries=[] ==>
    leaf_variable_count Independent.queries<=leaf_candidate_budget qr qs /\ size res<=12].
proof.
  move=> hr hs; exact (leaf_target_byte_candidate_cost A qr qs hr hs).
qed.
