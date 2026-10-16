(* Variable-candidate accounting for the actual opening-redacted chain backend. *)
require import AllCore List RadixEncoding.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle.
require import ChainValueView RedactedChainOracle ChainVariableBasicCost.

require import LeafCandidateCount LeafGrindingCandidates.

lemma chain_variable_wots_sign_public_cost q :
  hoare[ChainWots(RedactedCachedChain).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+305].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries<=q).
  + call (chain_variable_count_public_cost q); auto.
  sp 1; if; last by auto; smt().
  wp; seq 2 : (leaf_variable_count Independent.queries<=q+4).
  + exists* Independent.queries; elim* => qs;
      call (chain_variable_shuffle_permutation_public_cost (leaf_variable_count qs)); auto; smt().
  while (0<=step<=43 /\ leaf_variable_count Independent.queries<=q+4+7*step).
  + wp; exists* Independent.queries; elim* => qs;
      call (chain_variable_cached_value_cost (leaf_variable_count qs)); auto; smt(raw_digit_bounds).
  auto; smt().
qed.
