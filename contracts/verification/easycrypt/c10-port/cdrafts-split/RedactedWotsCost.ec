(* Cached positions reduce physical queries without changing the original WOTS budget. *)
require import AllCore List RadixEncoding.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle.
require import ChainValueView RedactedChainOracle RedactedBasicCost.

lemma redacted_wots_sign_public_cost q :
  hoare[ChainWots(RedactedCachedChain).sign : size Independent.queries=q ==>
    q<=size Independent.queries<=q+signing_budget+305].
proof.
  proc; seq 1 : (q<=size Independent.queries<=q+signing_budget).
  + call (redacted_count_public_cost q); auto.
  sp 1; if; last by auto; smt().
  wp; seq 2 : (q<=size Independent.queries<=q+signing_budget+4).
  + exists* Independent.queries; elim* => qs;
      call (redacted_shuffle_permutation_public_cost (size qs)); auto; smt().
  while (0<=step<=43 /\ q<=size Independent.queries<=q+signing_budget+4+7*step).
  + wp; exists* Independent.queries; elim* => qs;
      call (redacted_cached_value_cost (size qs)); auto; smt(raw_digit_bounds).
  auto; smt().
qed.
