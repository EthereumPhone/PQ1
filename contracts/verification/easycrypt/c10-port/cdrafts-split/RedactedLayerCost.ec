(* Whole-signer query budget for the opening-redacted chain simulator. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawWots RawWotsCost RawShuffle RawMerkle RawMerkleCost RawLayer.

require import ChainValueView ChainLayerView ChainSignerView RedactedChainOracle RedactedBasicCost RedactedWotsCost RedactedMerkleCost RedactedForestCost.

lemma redacted_layer_recover_public_cost q :
  hoare[ChainLayer(RedactedCachedChain).recover : size Independent.queries = q ==>
    q <= size Independent.queries <= q+312 /\ size res = 16].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+303).
  + call (redacted_wots_recover_public_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (redacted_merkle_recover_public_cost (size zs)); auto; smt().
qed.

lemma redacted_layer_sign_public_cost q :
  hoare[ChainLayer(RedactedCachedChain).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+signing_budget+155753].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+155135).
  + call (redacted_merkle_build_public_cost q); auto; smt().
  seq 1 : (q <= size Independent.queries <= q+155136).
  + exists* Independent.queries; elim* => zs; call (redacted_shuffle_derive_public_cost (size zs)); auto; smt().
  seq 1 : (q <= size Independent.queries <= q+signing_budget+155441).
  + exists* Independent.queries; elim* => zs; call (redacted_wots_sign_public_cost (size zs)); auto; smt().
  sp 1; if; last by auto; smt().
  wp; exists* Independent.queries; elim* => zs; call (redacted_layer_recover_public_cost (size zs)); auto; smt().
qed.


lemma redacted_raw_layer_recover_public_cost q :
  hoare[RawLayer(PreparationView(ChainPrefix(RedactedCachedChain))).recover : size Independent.queries = q ==>
    q <= size Independent.queries <= q+312 /\ size res = 16].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+303).
  + call (redacted_wots_recover_public_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (redacted_merkle_recover_public_cost (size zs)); auto; smt().
qed.
