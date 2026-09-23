(* Actual loop query accounting after the shared-secret hybrid. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid RoleGrind.

lemma independent_hash_count q0 :
  hoare[Independent.hash : size Independent.queries = q0 ==>
    size Independent.queries = q0+1].
proof. by proc; sp 1; if; auto; smt(size_rcons). qed.
lemma independent_derive_count q0 :
  hoare[Independent.derive : size Independent.queries = q0 ==>
    size Independent.queries = q0].
proof. by proc; if; auto. qed.

lemma role_grind_public_cost q0 :
  hoare[RoleGrind(Independent).run : size Independent.queries = q0 ==>
    q0 <= size Independent.queries <= q0 + signing_budget].
proof.
  proc; while (0 <= i <= signing_budget /\ size Independent.queries = q0+i).
  + exists* i; elim* => i0; wp; call (independent_hash_count (q0+i0)).
    wp; call (independent_derive_count (q0+i0)); auto; smt().
  by auto; smt().
qed.

lemma role_grind_lossless (O <: PrefixOracle) :
  islossless O.hash => islossless O.derive => islossless RoleGrind(O).run.
proof.
  move=> hh hd; proc; while true (signing_budget-i).
  + move=> z; wp; call hh; wp; call hd; auto; smt().
  by auto; smt().
qed.
