(* WOTS count calls have zero node-domain cost; all chain/recovery calls remain bounded. *)
require import AllCore List Distr IntDiv RadixEncoding.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle.
require import DomainQueryCount NodeQueryDomain DomainShuffleCost ClientGuessCandidates.

lemma domain_count_cost q :
  hoare[RawWots(PreparationView(Independent)).count : size seed=32 /\ size message=16 /\
    node_query_count Independent.queries<=q ==> node_query_count Independent.queries<=q].
proof.
  proc; while (size seed=32 /\ size message=16 /\ node_query_count Independent.queries<=q).
  + wp; call (domain_hash_nonnode q); auto; smt(node_query_no_count).
  auto.
qed.

lemma domain_chain_cost q :
  hoare[RawWots(PreparationView(Independent)).chain :
    node_query_count Independent.queries <= q /\ 0 <= start <= stop <= 7 ==>
    node_query_count Independent.queries <= q+7].
proof.
  proc; while (0 <= start <= j <= stop <= 7 /\ node_query_count Independent.queries <= q+j-start).
  + exists* j, start; elim* => j0 s; wp; call (domain_hash_bound (q+j0-s)); auto; smt().
  auto; smt().
qed.

lemma domain_wots_recover_cost q :
  hoare[RawWots(PreparationView(Independent)).recover : node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+303 /\ size res = 16].
proof.
  proc; seq 1 : (node_query_count Independent.queries <= q+1).
  + call (domain_hash_bound q); auto.
  sp 1; if; last by auto; smt(size_nseq).
  seq 3 : (node_query_count Independent.queries <= q+302).
  + while (0 <= i <= 43 /\ node_query_count Independent.queries <= q+1+7*i).
    - wp; exists* Independent.queries; elim* => qs1; call (domain_chain_cost (node_query_count qs1)); auto; smt(raw_digit_bounds).
    auto; smt().
  wp; exists* Independent.queries; elim* => qs; call (domain_hash_bound (node_query_count qs)); auto; smt(node_width).
qed.

lemma domain_wots_sign_cost q :
  hoare[RawWots(PreparationView(Independent)).sign : size seed=32 /\ size message=16 /\ node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+305].
proof.
  proc; seq 1 : (node_query_count Independent.queries <= q).
  + call (domain_count_cost q); auto.
  sp 1; if; last by auto; smt().
  wp; seq 2 : (node_query_count Independent.queries <= q+4).
  + exists* Independent.queries; elim* => qs; call (domain_shuffle_permutation_cost (node_query_count qs)); auto; smt().
  while (0 <= step <= 43 /\ node_query_count Independent.queries <= q+4+7*step).
  + seq 2 : (0 <= step < 43 /\ node_query_count Independent.queries <= q+4+7*step).
    - exists* Independent.queries; elim* => qs; call (domain_wots_bound (node_query_count qs)); auto; smt().
    wp; exists* Independent.queries; elim* => qs; call (domain_chain_cost (node_query_count qs)); auto; smt(raw_digit_bounds).
  auto; smt().
qed.
