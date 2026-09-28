(* Query accounting for the complete FORS forest, including shuffle hashes. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import RawFors RawForsCost RawShuffle RawForest PhysicalKeygenCost RoleGrindCost.

lemma forest_one_physical_cost c :
  hoare[RawForest(PreparationView(Physical)).one : Shared.calls = c ==>
    c <= Shared.calls <= c+6156].
proof.
  proc; seq 1 : (c <= Shared.calls <= c+6144).
  + call (fors_sign_physical_cost c); auto; smt().
  exists* Shared.calls; elim* => z; call (fors_recover_physical_cost z); auto; smt().
qed.

lemma forest_sign_physical_cost c :
  hoare[RawForest(PreparationView(Physical)).sign : Shared.calls = c ==>
    c <= Shared.calls <= c+80022 /\ size res.`3 = 16].
proof.
  proc; seq 5 : (c <= Shared.calls <= c+5).
  + seq 4 : (c <= Shared.calls <= c+1).
    - call (shuffle_derive_physical_cost c); auto.
    exists* Shared.calls; elim* => z; call (shuffle_permutation_physical_cost z); auto; smt().
  seq 2 : (c <= Shared.calls <= c+73877).
  + while (0 <= step <= 12 /\ c <= Shared.calls <= c+5+6156*step).
    - wp; exists* Shared.calls; elim* => z; call (forest_one_physical_cost z); auto; smt().
    auto; smt().
  seq 1 : (c <= Shared.calls <= c+80020).
  + exists* Shared.calls; elim* => z; call (fors_root_physical_cost z); auto; smt().
  seq 2 : (c <= Shared.calls <= c+80021).
  + exists* Shared.calls; elim* => z; call (physical_hash_count z); auto; smt().
  exists* Shared.calls; elim* => z; call (physical_hash_count z); auto; smt(node_width).
qed.

lemma forest_recover_physical_cost c :
  hoare[RawForest(PreparationView(Physical)).recover : Shared.calls = c ==>
    Shared.calls = c+146 /\ size res = 16].
proof.
  proc; call (physical_hash_count (c+145)); wp; call (physical_hash_count (c+144)).
  while (0 <= t <= 12 /\ Shared.calls = c+12*t).
  + exists* t; elim* => t0; wp; call (fors_recover_physical_cost (c+12*t0)); auto; smt().
  auto; smt(node_width).
qed.

lemma forest_one_public_cost q :
  hoare[RawForest(PreparationView(Independent)).one : size Independent.queries = q ==>
    q <= size Independent.queries <= q+4107].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+4095).
  + call (fors_sign_public_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (fors_recover_public_cost (size zs)); auto; smt().
qed.

lemma forest_sign_public_cost q :
  hoare[RawForest(PreparationView(Independent)).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+53386 /\ size res.`3 = 16].
proof.
  proc; seq 5 : (q <= size Independent.queries <= q+5).
  + seq 4 : (q <= size Independent.queries <= q+1).
    - call (shuffle_derive_public_cost q); auto.
    exists* Independent.queries; elim* => zs; call (shuffle_permutation_public_cost (size zs)); auto; smt().
  seq 2 : (q <= size Independent.queries <= q+49289).
  + while (0 <= step <= 12 /\ q <= size Independent.queries <= q+5+4107*step).
    - wp; exists* Independent.queries; elim* => zs; call (forest_one_public_cost (size zs)); auto; smt().
    auto; smt().
  seq 1 : (q <= size Independent.queries <= q+53384).
  + exists* Independent.queries; elim* => zs; call (fors_root_public_cost (size zs)); auto; smt().
  seq 2 : (q <= size Independent.queries <= q+53385).
  + exists* Independent.queries; elim* => zs; call (independent_hash_count (size zs)); auto; smt().
  exists* Independent.queries; elim* => zs; call (independent_hash_count (size zs)); auto; smt(node_width).
qed.

lemma forest_recover_public_cost q :
  hoare[RawForest(PreparationView(Independent)).recover : size Independent.queries = q ==>
    size Independent.queries = q+146 /\ size res = 16].
proof.
  proc; call (independent_hash_count (q+145)); wp; call (independent_hash_count (q+144)).
  while (0 <= t <= 12 /\ size Independent.queries = q+12*t).
  + exists* t; elim* => t0; wp; call (fors_recover_public_cost (q+12*t0)); auto; smt().
  auto; smt(node_width).
qed.
