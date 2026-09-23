(* Worst-case query counts include every WOTS search and chain call. *)
require import AllCore List Distr IntDiv RadixEncoding.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen PhysicalKeygenCost RoleGrindCost RawShuffle RawWots.

lemma count_physical_cost c :
  hoare[RawWots(PreparationView(Physical)).count : Shared.calls = c ==>
    c <= Shared.calls <= c+signing_budget].
proof.
  proc; while (0 <= i <= signing_budget /\ Shared.calls = c+i).
  + exists* i; elim* => i0; wp; call (physical_hash_count (c+i0)); auto; smt().
  auto; smt().
qed.
lemma count_public_cost q :
  hoare[RawWots(PreparationView(Independent)).count : size Independent.queries = q ==>
    q <= size Independent.queries <= q+signing_budget].
proof.
  proc; while (0 <= i <= signing_budget /\ size Independent.queries = q+i).
  + exists* i; elim* => i0; wp; call (independent_hash_count (q+i0)); auto; smt().
  auto; smt().
qed.
lemma chain_physical_cost c :
  hoare[RawWots(PreparationView(Physical)).chain :
    Shared.calls = c /\ 0 <= start <= stop <= 7 ==>
    c <= Shared.calls <= c+7].
proof.
  proc; while (0 <= start <= j <= stop <= 7 /\ Shared.calls = c+j-start).
  + exists* j, start; elim* => j0 s; wp; call (physical_hash_count (c+j0-s)); auto; smt().
  auto; smt().
qed.
lemma chain_public_cost q :
  hoare[RawWots(PreparationView(Independent)).chain :
    size Independent.queries = q /\ 0 <= start <= stop <= 7 ==>
    q <= size Independent.queries <= q+7].
proof.
  proc; while (0 <= start <= j <= stop <= 7 /\ size Independent.queries = q+j-start).
  + exists* j, start; elim* => j0 s; wp; call (independent_hash_count (q+j0-s)); auto; smt().
  auto; smt().
qed.

lemma wots_sign_physical_cost c :
  hoare[RawWots(PreparationView(Physical)).sign : Shared.calls = c ==>
    c <= Shared.calls <= c+signing_budget+348].
proof.
  proc; seq 1 : (c <= Shared.calls <= c+signing_budget).
  + call (count_physical_cost c); auto.
  sp 1; if; last by auto; smt().
  wp; seq 2 : (c <= Shared.calls <= c+signing_budget+4).
  + exists* Shared.calls; elim* => c0; call (shuffle_permutation_physical_cost c0); auto; smt().
  while (0 <= step <= 43 /\ c <= Shared.calls <= c+signing_budget+4+8*step).
  + seq 2 : (0 <= step < 43 /\ c <= Shared.calls <= c+signing_budget+4+8*step+1).
    - exists* Shared.calls; elim* => c0; call (physical_wots_count c0); auto; smt().
    wp; exists* Shared.calls; elim* => c0; call (chain_physical_cost c0); auto; smt(raw_digit_bounds).
  auto; smt().
qed.

lemma wots_sign_public_cost q :
  hoare[RawWots(PreparationView(Independent)).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+signing_budget+305].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+signing_budget).
  + call (count_public_cost q); auto.
  sp 1; if; last by auto; smt().
  wp; seq 2 : (q <= size Independent.queries <= q+signing_budget+4).
  + exists* Independent.queries; elim* => qs; call (shuffle_permutation_public_cost (size qs)); auto; smt().
  while (0 <= step <= 43 /\ q <= size Independent.queries <= q+signing_budget+4+7*step).
  + seq 2 : (0 <= step < 43 /\ q <= size Independent.queries <= q+signing_budget+4+7*step).
    - exists* Independent.queries; elim* => qs; call (wots_public_count (size qs)); auto; smt().
    wp; exists* Independent.queries; elim* => qs; call (chain_public_cost (size qs)); auto; smt(raw_digit_bounds).
  auto; smt().
qed.

lemma wots_recover_physical_cost c :
  hoare[RawWots(PreparationView(Physical)).recover : Shared.calls = c ==>
    c <= Shared.calls <= c+303 /\ size res = 16].
proof.
  proc; seq 1 : (Shared.calls = c+1).
  + call (physical_hash_count c); auto.
  sp 1; if; last by auto; smt(size_nseq).
  seq 3 : (c+1 <= Shared.calls <= c+302).
  + while (0 <= i <= 43 /\ c+1 <= Shared.calls <= c+1+7*i).
    - wp; exists* Shared.calls; elim* => c1; call (chain_physical_cost c1); auto; smt(raw_digit_bounds).
    auto; smt().
  wp; exists* Shared.calls; elim* => c0; call (physical_hash_count c0); auto; smt(node_width).
qed.

lemma wots_recover_public_cost q :
  hoare[RawWots(PreparationView(Independent)).recover : size Independent.queries = q ==>
    q <= size Independent.queries <= q+303 /\ size res = 16].
proof.
  proc; seq 1 : (size Independent.queries = q+1).
  + call (independent_hash_count q); auto.
  sp 1; if; last by auto; smt(size_nseq).
  seq 3 : (q+1 <= size Independent.queries <= q+302).
  + while (0 <= i <= 43 /\ q+1 <= size Independent.queries <= q+1+7*i).
    - wp; exists* Independent.queries; elim* => qs1; call (chain_public_cost (size qs1)); auto; smt(raw_digit_bounds).
    auto; smt().
  wp; exists* Independent.queries; elim* => qs; call (independent_hash_count (size qs)); auto; smt(node_width).
qed.
