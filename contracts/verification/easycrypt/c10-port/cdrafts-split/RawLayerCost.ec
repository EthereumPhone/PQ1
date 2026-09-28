(* One full hypertree layer: build, shuffle, bounded WOTS and reconstruction. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawWots RawWotsCost RawShuffle RawMerkle RawMerkleCost RawLayer.

lemma layer_recover_physical_cost c :
  hoare[RawLayer(PreparationView(Physical)).recover : Shared.calls = c ==>
    c <= Shared.calls <= c+312 /\ size res = 16].
proof.
  proc; seq 1 : (c <= Shared.calls <= c+303).
  + call (wots_recover_physical_cost c); auto; smt().
  exists* Shared.calls; elim* => z; call (merkle_recover_physical_cost z); auto; smt().
qed.
lemma layer_sign_physical_cost c :
  hoare[RawLayer(PreparationView(Physical)).sign : Shared.calls = c ==>
    c <= Shared.calls <= c+signing_budget+177812].
proof.
  proc; seq 1 : (c <= Shared.calls <= c+177151).
  + call (merkle_build_physical_cost c); auto; smt().
  seq 1 : (c <= Shared.calls <= c+177152).
  + exists* Shared.calls; elim* => z; call (shuffle_derive_physical_cost z); auto; smt().
  seq 1 : (c <= Shared.calls <= c+signing_budget+177500).
  + exists* Shared.calls; elim* => z; call (wots_sign_physical_cost z); auto; smt().
  sp 1; if; last by auto; smt().
  wp; exists* Shared.calls; elim* => z; call (layer_recover_physical_cost z); auto; smt().
qed.

lemma layer_recover_public_cost q :
  hoare[RawLayer(PreparationView(Independent)).recover : size Independent.queries = q ==>
    q <= size Independent.queries <= q+312 /\ size res = 16].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+303).
  + call (wots_recover_public_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (merkle_recover_public_cost (size zs)); auto; smt().
qed.
lemma layer_sign_public_cost q :
  hoare[RawLayer(PreparationView(Independent)).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+signing_budget+155753].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+155135).
  + call (merkle_build_public_cost q); auto; smt().
  seq 1 : (q <= size Independent.queries <= q+155136).
  + exists* Independent.queries; elim* => zs; call (shuffle_derive_public_cost (size zs)); auto; smt().
  seq 1 : (q <= size Independent.queries <= q+signing_budget+155441).
  + exists* Independent.queries; elim* => zs; call (wots_sign_public_cost (size zs)); auto; smt().
  sp 1; if; last by auto; smt().
  wp; exists* Independent.queries; elim* => zs; call (layer_recover_public_cost (size zs)); auto; smt().
qed.
