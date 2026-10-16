(* Variable-candidate accounting for the actual opening-redacted chain backend. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawWots RawWotsCost RawShuffle RawMerkle RawMerkleCost RawLayer.

require import ChainValueView ChainLayerView ChainSignerView RedactedChainOracle ChainVariableBasicCost ChainVariableWotsCost ChainVariableMerkleCost ChainVariableForestCost.

require import LeafCandidateCount LeafGrindingCandidates.

lemma chain_variable_layer_recover_public_cost q :
  hoare[ChainLayer(RedactedCachedChain).recover : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+312 /\ size res = 16].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries <= q+303).
  + call (chain_variable_wots_recover_public_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (chain_variable_merkle_recover_public_cost (leaf_variable_count zs)); auto; smt().
qed.

lemma chain_variable_layer_sign_public_cost q :
  hoare[ChainLayer(RedactedCachedChain).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+155753].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries <= q+155135).
  + call (chain_variable_merkle_build_public_cost q); auto; smt().
  seq 1 : (leaf_variable_count Independent.queries <= q+155136).
  + exists* Independent.queries; elim* => zs; call (chain_variable_shuffle_derive_public_cost (leaf_variable_count zs)); auto; smt().
  seq 1 : (leaf_variable_count Independent.queries <= q+155441).
  + exists* Independent.queries; elim* => zs; call (chain_variable_wots_sign_public_cost (leaf_variable_count zs)); auto; smt().
  sp 1; if; last by auto; smt().
  wp; exists* Independent.queries; elim* => zs; call (chain_variable_layer_recover_public_cost (leaf_variable_count zs)); auto; smt().
qed.


lemma chain_variable_raw_layer_recover_public_cost q :
  hoare[RawLayer(PreparationView(ChainPrefix(RedactedCachedChain))).recover : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+312 /\ size res = 16].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries <= q+303).
  + call (chain_variable_wots_recover_public_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (chain_variable_merkle_recover_public_cost (leaf_variable_count zs)); auto; smt().
qed.
