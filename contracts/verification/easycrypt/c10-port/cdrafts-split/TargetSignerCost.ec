(* Whole-signer costs in the transformed target game. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid RoleGrindCost KeygenPrefixes.
require import RawKeygen RawKeygenCost RawFors RawLayer RawForest RawSigner RoleGrind.
require import ForsLeafView LeafForestView TargetOracleSplit TargetByteView TargetSignerProjection TargetAdapterCost TargetForsCost.
lemma target_fors_recover_public_cost q :
  hoare[RawFors(IdealPreparation).recover : size Independent.queries = q ==>
    size Independent.queries = q+12 /\ size res = 16].
proof.
  proc; while (0 <= h <= 11 /\ size Independent.queries = q+1+h /\ size current = 16).
  + exists* h; elim* => h0; wp; call (independent_hash_count (q+1+h0)); auto; smt(node_width).
  wp; call (independent_hash_count q); auto; smt(node_width).
qed.

lemma target_forest_one_public_cost q :
  hoare[LeafForest(IdealPreparation,IdealLeaf).one : size Independent.queries = q ==>
    q <= size Independent.queries <= q+4107].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+4095).
  + call (target_fors_sign_public_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (target_fors_recover_public_cost (size zs)); auto; smt().
qed.

lemma target_forest_sign_public_cost q :
  hoare[LeafForest(IdealPreparation,IdealLeaf).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+53386 /\ size res.`3 = 16].
proof.
  proc; seq 5 : (q <= size Independent.queries <= q+5).
  + seq 4 : (q <= size Independent.queries <= q+1).
    - call (target_shuffle_derive_public_cost q); auto.
    exists* Independent.queries; elim* => zs; call (target_shuffle_permutation_public_cost (size zs)); auto; smt().
  seq 2 : (q <= size Independent.queries <= q+49289).
  + while (0 <= step <= 12 /\ q <= size Independent.queries <= q+5+4107*step).
    - wp; exists* Independent.queries; elim* => zs; call (target_forest_one_public_cost (size zs)); auto; smt().
    auto; smt().
  seq 1 : (q <= size Independent.queries <= q+53384).
  + exists* Independent.queries; elim* => zs; call (target_fors_root_public_cost (size zs)); auto; smt().
  seq 2 : (q <= size Independent.queries <= q+53385).
  + exists* Independent.queries; elim* => zs; call (independent_hash_count (size zs)); auto; smt().
  exists* Independent.queries; elim* => zs; call (independent_hash_count (size zs)); auto; smt(node_width).
qed.

lemma target_forest_recover_public_cost q :
  hoare[RawForest(IdealPreparation).recover : size Independent.queries = q ==>
    size Independent.queries = q+146 /\ size res = 16].
proof.
  proc; call (independent_hash_count (q+145)); wp; call (independent_hash_count (q+144)).
  while (0 <= t <= 12 /\ size Independent.queries = q+12*t).
  + exists* t; elim* => t0; wp; call (target_fors_recover_public_cost (q+12*t0)); auto; smt().
  auto; smt(node_width).
qed.

lemma target_role_grind_public_cost q0 :
  hoare[RoleGrind(IdealPrefix).run : size Independent.queries = q0 ==>
    q0 <= size Independent.queries <= q0 + signing_budget].
proof.
  proc; while (0 <= i <= signing_budget /\ size Independent.queries = q0+i).
  + exists* i; elim* => i0; wp; call (independent_hash_count (q0+i0)).
    wp; call (target_derive_count (q0+i0)); auto; smt().
  by auto; smt().
qed.

lemma target_signer_finish_public_cost q :
  hoare[TargetSigning(IdealTarget).finish : size Independent.queries = q ==>
    q <= size Independent.queries <= q+2*signing_budget+364892].
proof.
  proc; seq 2 : (q <= size Independent.queries <= q+53386).
  + call (target_forest_sign_public_cost q); auto; smt().
  wp; while (0 <= layer <= 2 /\ q <= size Independent.queries <= q+53386+layer*(signing_budget+155753)).
  + wp; exists* Independent.queries; elim* => zs; call (target_layer_sign_public_cost (size zs)); auto; smt().
  auto; rewrite /signing_budget; smt().
qed.

lemma target_signer_sign_public_cost q :
  hoare[TargetSigning(IdealTarget).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+3*signing_budget+364892].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+1*signing_budget).
  + call (target_role_grind_public_cost q); auto; smt().
  sp 1; if; last by auto; rewrite /signing_budget; smt().
  exists* Independent.queries; elim* => zs; call (target_signer_finish_public_cost (size zs)); auto; smt().
qed.

lemma target_signer_verify_public_cost q :
  hoare[RawSigner(IdealPrefix).verify : size Independent.queries = q ==>
    q <= size Independent.queries <= q+771].
proof.
  proc; seq 1 : (size Independent.queries = q+1).
  + call (independent_hash_count q); auto.
  sp 1; if; last by auto; smt().
  seq 2 : (size Independent.queries = q+147).
  + call (target_forest_recover_public_cost (q+1)); auto; smt().
  wp; while (0 <= layer <= 2 /\ q+147 <= size Independent.queries <= q+147+312*layer).
  + wp; exists* Independent.queries; elim* => zs; call (target_layer_recover_public_cost (size zs)); auto; smt().
  auto; smt().
qed.
