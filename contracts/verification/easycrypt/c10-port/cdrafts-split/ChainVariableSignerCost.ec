(* Variable-candidate accounting for the actual opening-redacted chain backend. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen PhysicalKeygenCost RoleGrind RoleGrindCost.
require import RawForest RawForestCost RawLayer RawLayerCost RawSigner.

require import ChainValueView ChainLayerView ChainSignerView RedactedChainOracle ChainVariableBasicCost ChainVariableWotsCost ChainVariableMerkleCost ChainVariableForestCost ChainVariableLayerCost.

require import LeafCandidateCount LeafGrindingCandidates.

lemma chain_variable_signer_finish_public_cost q :
  hoare[ChainSigner(RedactedCachedChain).finish : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+364892].
proof.
  proc; seq 2 : (leaf_variable_count Independent.queries <= q+53386).
  + call (chain_variable_forest_sign_public_cost q); auto; smt().
  wp; while (0 <= layer <= 2 /\ leaf_variable_count Independent.queries <= q+53386+layer*(155753)).
  + wp; exists* Independent.queries; elim* => zs; call (chain_variable_layer_sign_public_cost (leaf_variable_count zs)); auto; smt().
  auto; rewrite /signing_budget; smt().
qed.

lemma chain_variable_signer_sign_public_cost q :
  hoare[ChainSigner(RedactedCachedChain).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+364892].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries <= q).
  + call (chain_variable_role_grind_public_cost q); auto; smt().
  sp 1; if; last by auto; rewrite /signing_budget; smt().
  exists* Independent.queries; elim* => zs; call (chain_variable_signer_finish_public_cost (leaf_variable_count zs)); auto; smt().
qed.

lemma chain_variable_signer_verify_public_cost q :
  hoare[RawSigner(ChainPrefix(RedactedCachedChain)).verify : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+771].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries<=q+1).
  + call (leaf_variable_hash_bound q); auto.
  sp 1; if; last by auto; smt().
  seq 2 : (leaf_variable_count Independent.queries<=q+147).
  + call (chain_variable_forest_recover_public_cost (q+1)); auto; smt().
  wp; while (0 <= layer <= 2 /\ leaf_variable_count Independent.queries <= q+147+312*layer).
  + wp; exists* Independent.queries; elim* => zs; call (chain_variable_raw_layer_recover_public_cost (leaf_variable_count zs)); auto; smt().
  auto; smt().
qed.

