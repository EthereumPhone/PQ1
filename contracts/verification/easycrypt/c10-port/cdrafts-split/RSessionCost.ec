(* Adversary-independent cost enforced by the session's whole-run caps. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter PrefixGuess RoleGrind RoleGrindCost RSession.

lemma client_public_cost (A <: RClient {-RSession,-Independent}) q0 :
  hoare[A(RSession(Independent)).run :
    0 <= RSession.raw_calls <= RSession.raw_limit /\
    0 <= RSession.sign_calls <= RSession.sign_limit /\
    size Independent.queries <= q0+RSession.raw_calls+RSession.sign_calls*signing_budget ==>
    0 <= RSession.raw_calls <= RSession.raw_limit /\
    0 <= RSession.sign_calls <= RSession.sign_limit /\
    size Independent.queries <= q0+RSession.raw_calls+RSession.sign_calls*signing_budget].
proof.
  proc (0 <= RSession.raw_calls <= RSession.raw_limit /\
    0 <= RSession.sign_calls <= RSession.sign_limit /\
    size Independent.queries <= q0+RSession.raw_calls+RSession.sign_calls*signing_budget) => //.
  + proc; sp 1; if; last by auto.
    wp; exists* (size Independent.queries); elim* => q.
    call (independent_hash_count q); auto; smt().
  proc; sp 1; if; last by auto.
  wp; exists* (size Independent.queries); elim* => q.
  call (role_grind_public_cost q); auto; smt().
qed.

lemma client_lossless (A <: RClient {-RSession}) (O <: PrefixOracle {-A,-RSession}) :
  (forall (V <: RClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless A(RSession(O)).run.
proof.
  move=> ha hh hd; apply (ha (RSession(O))).
  + exact (session_hash_lossless O hh).
  exact (session_sign_lossless O hh hd).
qed.
