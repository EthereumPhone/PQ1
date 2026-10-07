(* Public-query budget of the concrete redacted target adapter. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RoleGrindCost.
require import RawKeygen RawKeygenCost KeygenExhaustion RawShuffle RawWots RawFors RawMerkle RawLayer RawForest RawSigner.
require import RadixEncoding ForsLeafView LeafForestView LeafSignerView LeafOpeningBound TargetOracleSplit TargetByteView TargetSignerProjection.
module IdealTarget = TargetKernelAdapter(RedactedLeafOpening(Independent)).
module IdealPrefix = TargetPrefix(IdealTarget).
module IdealPreparation = PreparationView(IdealPrefix).
module IdealLeaf = TargetLeaf(IdealTarget).

lemma target_derive_count q :
 hoare [IdealPrefix.derive : size Independent.queries=q ==> size Independent.queries=q].
proof.
 proc; if.
 + wp; call (_ : true ==> true); first by trivial.
   auto.
 call (_ : true ==> true); first by trivial.
 auto.
qed.
lemma target_wots_public_count q0 :
  hoare[IdealPreparation.wots : size Independent.queries = q0 ==>
    size Independent.queries = q0].
proof. by proc; call (target_derive_count q0); auto. qed.

lemma target_leaf_public_cost q0 :
  hoare[RawKeygen(IdealPreparation).leaf : size Independent.queries = q0 ==>
    size Independent.queries = q0 + 302 /\ size res = 16].
proof.
  proc; call (independent_hash_count (q0+301)); wp.
  while (0 <= i <= 43 /\ size Independent.queries = q0+7*i).
  + wp; while (0 <= j <= 7 /\ size Independent.queries = q0+7*i+j).
    - exists* i, j; elim* => i0 j0; wp.
      call (independent_hash_count (q0+7*i0+j0)); auto; smt().
    wp; exists* i; elim* => i0; call (target_wots_public_count (q0+7*i0)); auto; smt().
  auto; smt(node_width).
qed.

lemma target_root_public_cost q0 :
  hoare[RawKeygen(IdealPreparation).root : size Independent.queries = q0 ==>
    q0 <= size Independent.queries <= q0 + 155135 /\ size res = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ size Independent.queries = q0+303*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ size Independent.queries = q0+303*kp+302-size stack).
    - exists* kp, stack; elim* => kp0 st0.
      wp; call (independent_hash_count (q0+303*kp0+302-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (target_leaf_public_cost (q0+303*kp0-size st0)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma target_shuffle_derive_public_cost q :
  hoare[RawShuffle(IdealPreparation).derive : size Independent.queries = q ==>
    q <= size Independent.queries <= q+1].
proof. proc; sp 1; if.
  + wp; call (independent_hash_count q); auto; smt().
  auto; smt(). qed.

lemma target_shuffle_permutation_public_cost q :
  hoare[RawShuffle(IdealPreparation).permutation : size Independent.queries = q ==>
    q <= size Independent.queries <= q+4].
proof.
  proc; sp 1; if; last by auto; smt().
  while (size Independent.queries = q+4); first by auto.
  wp; while (0 <= blk <= 4 /\ size Independent.queries = q+blk).
  + exists* blk; elim* => b; wp; call (independent_hash_count (q+b)); auto; smt().
  auto; smt().
qed.

lemma target_count_public_cost q :
  hoare[RawWots(IdealPreparation).count : size Independent.queries = q ==>
    q <= size Independent.queries <= q+signing_budget].
proof.
  proc; while (0 <= i <= signing_budget /\ size Independent.queries = q+i).
  + exists* i; elim* => i0; wp; call (independent_hash_count (q+i0)); auto; smt().
  auto; smt().
qed.

lemma target_chain_public_cost q :
  hoare[RawWots(IdealPreparation).chain :
    size Independent.queries = q /\ 0 <= start <= stop <= 7 ==>
    q <= size Independent.queries <= q+7].
proof.
  proc; while (0 <= start <= j <= stop <= 7 /\ size Independent.queries = q+j-start).
  + exists* j, start; elim* => j0 s; wp; call (independent_hash_count (q+j0-s)); auto; smt().
  auto; smt().
qed.

lemma target_wots_sign_public_cost q :
  hoare[RawWots(IdealPreparation).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+signing_budget+305].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+signing_budget).
  + call (target_count_public_cost q); auto.
  sp 1; if; last by auto; smt().
  wp; seq 2 : (q <= size Independent.queries <= q+signing_budget+4).
  + exists* Independent.queries; elim* => qs; call (target_shuffle_permutation_public_cost (size qs)); auto; smt().
  while (0 <= step <= 43 /\ q <= size Independent.queries <= q+signing_budget+4+7*step).
  + seq 2 : (0 <= step < 43 /\ q <= size Independent.queries <= q+signing_budget+4+7*step).
    - exists* Independent.queries; elim* => qs; call (target_wots_public_count (size qs)); auto; smt().
    wp; exists* Independent.queries; elim* => qs; call (target_chain_public_cost (size qs)); auto; smt(raw_digit_bounds).
  auto; smt().
qed.

lemma target_wots_recover_public_cost q :
  hoare[RawWots(IdealPreparation).recover : size Independent.queries = q ==>
    q <= size Independent.queries <= q+303 /\ size res = 16].
proof.
  proc; seq 1 : (size Independent.queries = q+1).
  + call (independent_hash_count q); auto.
  sp 1; if; last by auto; smt(size_nseq).
  seq 3 : (q+1 <= size Independent.queries <= q+302).
  + while (0 <= i <= 43 /\ q+1 <= size Independent.queries <= q+1+7*i).
    - wp; exists* Independent.queries; elim* => qs1; call (target_chain_public_cost (size qs1)); auto; smt(raw_digit_bounds).
    auto; smt().
  wp; exists* Independent.queries; elim* => qs; call (independent_hash_count (size qs)); auto; smt(node_width).
qed.

lemma target_merkle_build_public_cost q :
  hoare[RawMerkle(IdealPreparation).build : size Independent.queries = q ==>
    q <= size Independent.queries <= q+155135 /\ size res.`2 = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ size Independent.queries = q+303*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ size Independent.queries = q+303*kp+302-size stack).
    - exists* kp, stack; elim* => kp0 st0.
      wp; call (independent_hash_count (q+303*kp0+302-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (target_leaf_public_cost (q+303*kp0-size st0)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma target_merkle_recover_public_cost q :
  hoare[RawMerkle(IdealPreparation).recover : size Independent.queries = q ==>
    size Independent.queries = q+9 /\ size res = 16].
proof.
  proc; while (0 <= h <= 9 /\ size Independent.queries = q+h /\ (0 < h => size current = 16)).
  + exists* h; elim* => h0; wp; call (independent_hash_count (q+h0)); auto; smt(node_width).
  auto; smt().
qed.

lemma target_layer_recover_public_cost q :
  hoare[RawLayer(IdealPreparation).recover : size Independent.queries = q ==>
    q <= size Independent.queries <= q+312 /\ size res = 16].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+303).
  + call (target_wots_recover_public_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (target_merkle_recover_public_cost (size zs)); auto; smt().
qed.

lemma target_layer_sign_public_cost q :
  hoare[RawLayer(IdealPreparation).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+signing_budget+155753].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+155135).
  + call (target_merkle_build_public_cost q); auto; smt().
  seq 1 : (q <= size Independent.queries <= q+155136).
  + exists* Independent.queries; elim* => zs; call (target_shuffle_derive_public_cost (size zs)); auto; smt().
  seq 1 : (q <= size Independent.queries <= q+signing_budget+155441).
  + exists* Independent.queries; elim* => zs; call (target_wots_sign_public_cost (size zs)); auto; smt().
  sp 1; if; last by auto; smt().
  wp; exists* Independent.queries; elim* => zs; call (target_layer_recover_public_cost (size zs)); auto; smt().
qed.
