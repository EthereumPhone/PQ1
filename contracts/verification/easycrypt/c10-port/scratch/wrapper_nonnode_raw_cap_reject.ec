require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RoleGrindCost.
require import RawSigner RawWrapperCost WrapperSession WrapperByteSession WrapperPrefixBound ExposureLog ClientQueryLog.
require import LeafOpeningBound TargetOracleSplit TargetByteView TargetAdapterCost TargetSignerCost TargetSessionCost.
require import WrapperTargetSession WrapperTargetContext WrapperLeafCandidateCost.
require import LeafCandidateCount LeafTargetSessionCost LeafTargetSignerCost.
require import WrapperLeafSessionCost.
lemma checked
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -OtherPrivate,-RedactedLeafState,-TargetConfig}) qr qs :
  0<=qr => 0<=qs =>
  hoare [TargetWrapperByteCandidates(A,IdealTarget).run :
    WrapperLimits.sign_cap=qs /\ Independent.queries=[] ==>
    leaf_variable_count Independent.queries<=wrapper_leaf_candidate_budget qr qs /\ size res<=12].
proof. exact (wrapper_leaf_byte_cost A qr qs). qed.
