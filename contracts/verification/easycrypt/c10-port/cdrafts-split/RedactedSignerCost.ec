(* Whole-signer query budget for the opening-redacted chain simulator. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen PhysicalKeygenCost RoleGrind RoleGrindCost.
require import RawForest RawForestCost RawLayer RawLayerCost RawSigner.

require import ChainValueView ChainLayerView ChainSignerView RedactedChainOracle RedactedBasicCost RedactedWotsCost RedactedMerkleCost RedactedForestCost RedactedLayerCost.

lemma redacted_signer_finish_public_cost q :
  hoare[ChainSigner(RedactedCachedChain).finish : size Independent.queries = q ==>
    q <= size Independent.queries <= q+2*signing_budget+364892].
proof.
  proc; seq 2 : (q <= size Independent.queries <= q+53386).
  + call (redacted_forest_sign_public_cost q); auto; smt().
  wp; while (0 <= layer <= 2 /\ q <= size Independent.queries <= q+53386+layer*(signing_budget+155753)).
  + wp; exists* Independent.queries; elim* => zs; call (redacted_layer_sign_public_cost (size zs)); auto; smt().
  auto; rewrite /signing_budget; smt().
qed.

lemma redacted_signer_sign_public_cost q :
  hoare[ChainSigner(RedactedCachedChain).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+3*signing_budget+364892].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+1*signing_budget).
  + call (redacted_role_grind_public_cost q); auto; smt().
  sp 1; if; last by auto; rewrite /signing_budget; smt().
  exists* Independent.queries; elim* => zs; call (redacted_signer_finish_public_cost (size zs)); auto; smt().
qed.

lemma redacted_signer_verify_public_cost q :
  hoare[RawSigner(ChainPrefix(RedactedCachedChain)).verify : size Independent.queries = q ==>
    q <= size Independent.queries <= q+771].
proof.
  proc; seq 1 : (size Independent.queries = q+1).
  + call (independent_hash_count q); auto.
  sp 1; if; last by auto; smt().
  seq 2 : (size Independent.queries = q+147).
  + call (redacted_forest_recover_public_cost (q+1)); auto; smt().
  wp; while (0 <= layer <= 2 /\ q+147 <= size Independent.queries <= q+147+312*layer).
  + wp; exists* Independent.queries; elim* => zs; call (redacted_raw_layer_recover_public_cost (size zs)); auto; smt().
  auto; smt().
qed.

