require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RoleGrindCost.
require import RawSigner RawWrapperCost WrapperSession WrapperByteSession WrapperPrefixBound ExposureLog ClientQueryLog.
require import LeafOpeningBound TargetOracleSplit TargetByteView TargetAdapterCost TargetSignerCost TargetSessionCost.
require import WrapperTargetSession WrapperTargetContext WrapperLeafCandidateCost.
require import LeafCandidateCount LeafTargetSessionCost LeafTargetSignerCost.
require import WrapperLeafSessionCost.
lemma checked
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent,-OtherPrivate,-RedactedLeafState,-TargetConfig}) q0 qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare [TargetWrapperDriver(A,IdealTarget).run : qr=qr0 /\ qs=qs0 /\ leaf_variable_count Independent.queries<=q0 ==>
    leaf_variable_count Independent.queries<=q0+qr0+qs0*wrapper_leaf_public_budget+771].
proof. exact (wrapper_leaf_driver_cost A q0 qr0 qs0). qed.
