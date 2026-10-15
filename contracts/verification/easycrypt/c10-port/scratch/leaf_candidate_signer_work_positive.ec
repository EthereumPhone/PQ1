require import AllCore List Distr IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid RoleGrindCost KeygenPrefixes.
require import RawKeygen RawKeygenCost RawFors RawLayer RawForest RawSigner RoleGrind.
require import ForsLeafView LeafForestView TargetOracleSplit TargetByteView TargetSignerProjection TargetAdapterCost LeafTargetForsCost LeafTargetOracleCost LeafCandidateCount LeafGrindingCandidates LeafBudgetLayer LeafBudgetShuffle.
require import LeafTargetSignerCost.

lemma checked q :
  hoare[TargetSigning(IdealTarget).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<= q+364892].
proof.
  exact (leaf_target_signer_sign_candidate_cost q).
qed.
