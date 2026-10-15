require import AllCore List Distr IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid RoleGrindCost KeygenPrefixes.
require import RawKeygen RawKeygenCost RawFors RawLayer RawForest RawSigner RoleGrind.
require import ForsLeafView LeafForestView TargetOracleSplit TargetByteView TargetSignerProjection TargetAdapterCost LeafTargetForsCost LeafTargetOracleCost LeafCandidateCount LeafGrindingCandidates LeafBudgetLayer LeafBudgetShuffle.
require import LeafTargetSignerCost.

lemma checked q :
  hoare[RawSigner(IdealPrefix).verify : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<= q].
proof.
  exact (leaf_target_signer_verify_candidate_cost q).
qed.
