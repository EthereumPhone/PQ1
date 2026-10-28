require import AllCore List IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawSigner.
require import RoleGrindCost ForsLeafView LeafOpeningBound TargetOracleSplit TargetByteView.
require import TargetAdapterCost LeafCandidateCount LeafTargetForsCost LeafTargetSignerCost LeafBudgetLayer LeafBudgetShuffle.
require import WrapperForsPlan WrapperForestPlan WrapperForestRelease WrapperSigningPlan WrapperPlanSigner WrapperReleasedFors.
require import WrapperOpeningFrames WrapperTargetProjection.
require import WrapperLeafCandidateCost.
lemma checked q :
  hoare [TargetWrapperReleased(IdealTarget).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+2*364892+771].
proof. exact (wrapper_leaf_release_cost q). qed.
