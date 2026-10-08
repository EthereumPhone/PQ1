(* Public-query bounds for the opening-redacted chain backend. *)
require import AllCore List Distr IntDiv RadixEncoding.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import RoleGrind RoleGrindCost RawShuffle RawWots RedactedChainOracle ChainValueView.

lemma redacted_derive_count q :
  hoare[RedactedChainPrefix.derive : size Independent.queries=q ==> size Independent.queries=q].
proof. proc; if; auto; call (independent_derive_count q); auto. qed.

lemma redacted_role_grind_public_cost q0 :
  hoare[RoleGrind(ChainPrefix(RedactedCachedChain)).run : size Independent.queries = q0 ==>
    q0 <= size Independent.queries <= q0 + signing_budget].
proof.
  proc; while (0 <= i <= signing_budget /\ size Independent.queries = q0+i).
  + exists* i; elim* => i0; wp; call (independent_hash_count (q0+i0)).
    wp; call (redacted_derive_count (q0+i0)); auto; smt().
  by auto; smt().
qed.

lemma redacted_shuffle_derive_public_cost q :
  hoare[RawShuffle(PreparationView(ChainPrefix(RedactedCachedChain))).derive : size Independent.queries = q ==>
    q <= size Independent.queries <= q+1].
proof. proc; sp 1; if.
  + wp; call (independent_hash_count q); auto; smt().
  auto; smt(). qed.

lemma redacted_shuffle_permutation_public_cost q :
  hoare[RawShuffle(PreparationView(ChainPrefix(RedactedCachedChain))).permutation : size Independent.queries = q ==>
    q <= size Independent.queries <= q+4].
proof.
  proc; sp 1; if; last by auto; smt().
  while (size Independent.queries = q+4); first by auto.
  wp; while (0 <= blk <= 4 /\ size Independent.queries = q+blk).
  + exists* blk; elim* => b; wp; call (independent_hash_count (q+b)); auto; smt().
  auto; smt().
qed.

lemma redacted_count_public_cost q :
  hoare[RawWots(PreparationView(ChainPrefix(RedactedCachedChain))).count : size Independent.queries = q ==>
    q <= size Independent.queries <= q+signing_budget].
proof.
  proc; while (0 <= i <= signing_budget /\ size Independent.queries = q+i).
  + exists* i; elim* => i0; wp; call (independent_hash_count (q+i0)); auto; smt().
  auto; smt().
qed.

lemma redacted_chain_public_cost q :
  hoare[RawWots(PreparationView(ChainPrefix(RedactedCachedChain))).chain :
    size Independent.queries = q /\ 0 <= start <= stop <= 7 ==>
    q <= size Independent.queries <= q+7].
proof.
  proc; while (0 <= start <= j <= stop <= 7 /\ size Independent.queries = q+j-start).
  + exists* j, start; elim* => j0 s; wp; call (independent_hash_count (q+j0-s)); auto; smt().
  auto; smt().
qed.

lemma redacted_wots_recover_public_cost q :
  hoare[RawWots(PreparationView(ChainPrefix(RedactedCachedChain))).recover : size Independent.queries = q ==>
    q <= size Independent.queries <= q+303 /\ size res = 16].
proof.
  proc; seq 1 : (size Independent.queries = q+1).
  + call (independent_hash_count q); auto.
  sp 1; if; last by auto; smt(size_nseq).
  seq 3 : (q+1 <= size Independent.queries <= q+302).
  + while (0 <= i <= 43 /\ q+1 <= size Independent.queries <= q+1+7*i).
    - wp; exists* Independent.queries; elim* => qs1; call (redacted_chain_public_cost (size qs1)); auto; smt(raw_digit_bounds).
    auto; smt().
  wp; exists* Independent.queries; elim* => qs; call (independent_hash_count (size qs)); auto; smt(node_width).
qed.

lemma redacted_raw_chain_public_cost q :
  hoare[RawWots(PreparationView(RedactedChainPrefix)).chain :
    size Independent.queries = q /\ 0 <= start <= stop <= 7 ==>
    q <= size Independent.queries <= q+7].
proof.
  proc; while (0 <= start <= j <= stop <= 7 /\ size Independent.queries = q+j-start).
  + exists* j, start; elim* => j0 s; wp; call (independent_hash_count (q+j0-s)); auto; smt().
  auto; smt().
qed.

lemma redacted_concrete_value_cost q :
  hoare[ConcreteChain(RedactedChainPrefix).value :
    size Independent.queries=q /\ 0<=stop<=7 ==>
    q<=size Independent.queries<=q+7].
proof.
  proc; call (redacted_raw_chain_public_cost q).
  wp; inline PreparationView(RedactedChainPrefix).wots.
  wp; call (redacted_derive_count q); auto.
qed.
lemma redacted_cached_value_cost q :
  hoare[RedactedCachedChain.value :
    size Independent.queries=q /\ 0<=stop<=7 ==>
    q<=size Independent.queries<=q+7].
proof.
  proc; if.
  + if; auto; smt().
  call (redacted_concrete_value_cost q); auto.
qed.
