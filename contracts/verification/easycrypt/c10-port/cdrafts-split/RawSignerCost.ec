(* Complete shared-oracle signer/verifier query accounting. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen PhysicalKeygenCost RoleGrind RoleGrindCost.
require import RawForest RawForestCost RawLayer RawLayerCost RawSigner.

lemma role_grind_physical_cost c :
  hoare[RoleGrind(Physical).run : Shared.calls = c ==>
    c <= Shared.calls <= c+2*signing_budget].
proof.
  proc; while (0 <= i <= signing_budget /\ Shared.calls = c+2*i).
  + exists* i; elim* => i0.
    seq 2 : (i = i0 /\ 0 <= i < signing_budget /\ Shared.calls = c+2*i0+1).
    - inline Physical.derive; wp; exists* Shared.draws; elim* => d0.
      call (hash_cost (c+2*i0) d0); auto; smt().
    wp; inline Physical.hash; wp; exists* Shared.draws; elim* => d1.
    call (hash_cost (c+2*i0+1) d1); auto; smt().
  auto; smt().
qed.

lemma signer_finish_physical_cost c :
  hoare[RawSigner(Physical).finish : Shared.calls = c ==>
    c <= Shared.calls <= c+2*signing_budget+435646].
proof.
  proc; seq 2 : (c <= Shared.calls <= c+80022).
  + call (forest_sign_physical_cost c); auto; smt().
  wp; while (0 <= layer <= 2 /\ c <= Shared.calls <= c+80022+layer*(signing_budget+177812)).
  + wp; exists* Shared.calls; elim* => z; call (layer_sign_physical_cost z); auto; smt().
  auto; rewrite /signing_budget; smt().
qed.
lemma signer_sign_physical_cost c :
  hoare[RawSigner(Physical).sign : Shared.calls = c ==>
    c <= Shared.calls <= c+4*signing_budget+435646].
proof.
  proc; seq 1 : (c <= Shared.calls <= c+2*signing_budget).
  + call (role_grind_physical_cost c); auto; smt().
  sp 1; if; last by auto; rewrite /signing_budget; smt().
  exists* Shared.calls; elim* => z; call (signer_finish_physical_cost z); auto; smt().
qed.
lemma signer_verify_physical_cost c :
  hoare[RawSigner(Physical).verify : Shared.calls = c ==>
    c <= Shared.calls <= c+771].
proof.
  proc; seq 1 : (Shared.calls = c+1).
  + call (physical_hash_count c); auto.
  sp 1; if; last by auto; smt().
  seq 2 : (Shared.calls = c+147).
  + call (forest_recover_physical_cost (c+1)); auto; smt().
  wp; while (0 <= layer <= 2 /\ c+147 <= Shared.calls <= c+147+312*layer).
  + wp; exists* Shared.calls; elim* => z; call (layer_recover_physical_cost z); auto; smt().
  auto; smt().
qed.

lemma signer_finish_public_cost q :
  hoare[RawSigner(Independent).finish : size Independent.queries = q ==>
    q <= size Independent.queries <= q+2*signing_budget+364892].
proof.
  proc; seq 2 : (q <= size Independent.queries <= q+53386).
  + call (forest_sign_public_cost q); auto; smt().
  wp; while (0 <= layer <= 2 /\ q <= size Independent.queries <= q+53386+layer*(signing_budget+155753)).
  + wp; exists* Independent.queries; elim* => zs; call (layer_sign_public_cost (size zs)); auto; smt().
  auto; rewrite /signing_budget; smt().
qed.
lemma signer_sign_public_cost q :
  hoare[RawSigner(Independent).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+3*signing_budget+364892].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+1*signing_budget).
  + call (role_grind_public_cost q); auto; smt().
  sp 1; if; last by auto; rewrite /signing_budget; smt().
  exists* Independent.queries; elim* => zs; call (signer_finish_public_cost (size zs)); auto; smt().
qed.
lemma signer_verify_public_cost q :
  hoare[RawSigner(Independent).verify : size Independent.queries = q ==>
    q <= size Independent.queries <= q+771].
proof.
  proc; seq 1 : (size Independent.queries = q+1).
  + call (independent_hash_count q); auto.
  sp 1; if; last by auto; smt().
  seq 2 : (size Independent.queries = q+147).
  + call (forest_recover_public_cost (q+1)); auto; smt().
  wp; while (0 <= layer <= 2 /\ q+147 <= size Independent.queries <= q+147+312*layer).
  + wp; exists* Independent.queries; elim* => zs; call (layer_recover_public_cost (size zs)); auto; smt().
  auto; smt().
qed.
