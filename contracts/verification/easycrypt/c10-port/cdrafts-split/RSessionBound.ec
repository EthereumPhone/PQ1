(* A first-failure bound for a whole adaptive grinding session. *)
require import AllCore List Distr FMap StdOrder StdBigop.
require import C10RawOracle C10RawGrind C10Counter.
require import PrefixGuess PrefixHybrid RoleGrind RoleGrindCost RawTrial RTailContexts.
require import GrindExhaustion ContextExhaustion RSession RSessionCost RSessionHistory KeygenPrefixes.
import RealOrder Bigreal BRA.

op valid_request (random message : raw_input) =
  size message = 32 /\ (size random = 0 \/ size random = 16).
op session_invariant q0 qr qs rc sc seed root contexts bad secret raw queries =
  0 <= rc <= qr /\ 0 <= sc <= qs /\ size seed = 32 /\ size root = 32 /\
  size queries <= q0+rc+sc*signing_budget /\
  session_history secret raw queries contexts seed root bad.

lemma session_bad_step q0 qr qs :
  phoare[RSession(Independent).sign :
    RSession.raw_limit = qr /\ RSession.sign_limit = qs /\
    !RSession.bad /\ valid_request random message /\ RSession.sign_calls < qs /\
    session_invariant q0 qr qs RSession.raw_calls RSession.sign_calls RSession.seed RSession.root
      RSession.contexts RSession.bad Independent.secrethistory Independent.rawhistory Independent.queries ==>
    RSession.bad] <= (exhaustion_charge (q0+qr+qs*signing_budget)).
proof.
  proc; rcondt 2; first by auto; rewrite /valid_request; smt().
  wp; exists* RSession.contexts; elim* => contexts.
  call (context_exhaustion (q0+qr+qs*signing_budget) contexts).
  auto; rewrite /session_invariant /session_history /valid_request /signing_budget; smt().
qed.

lemma session_sign_progress q0 qr qs c :
  hoare[RSession(Independent).sign :
    RSession.raw_limit = qr /\ RSession.sign_limit = qs /\ RSession.sign_calls = c /\
    valid_request random message /\ RSession.sign_calls < qs /\
    session_invariant q0 qr qs RSession.raw_calls RSession.sign_calls RSession.seed RSession.root
      RSession.contexts RSession.bad Independent.secrethistory Independent.rawhistory Independent.queries ==>
    RSession.raw_limit = qr /\ RSession.sign_limit = qs /\ RSession.sign_calls = c+1 /\
    session_invariant q0 qr qs RSession.raw_calls RSession.sign_calls RSession.seed RSession.root
      RSession.contexts RSession.bad Independent.secrethistory Independent.rawhistory Independent.queries].
proof.
  have hcost : hoare[RSession(Independent).sign :
    RSession.raw_limit = qr /\ RSession.sign_limit = qs /\ RSession.sign_calls = c /\
    valid_request random message /\ RSession.sign_calls < qs /\
    0 <= RSession.raw_calls <= qr /\ 0 <= RSession.sign_calls <= qs /\
    size RSession.seed = 32 /\ size RSession.root = 32 /\
    size Independent.queries <= q0+RSession.raw_calls+RSession.sign_calls*signing_budget ==>
    RSession.raw_limit = qr /\ RSession.sign_limit = qs /\ RSession.sign_calls = c+1 /\
    0 <= RSession.raw_calls <= qr /\ 0 <= RSession.sign_calls <= qs /\
    size RSession.seed = 32 /\ size RSession.root = 32 /\
    size Independent.queries <= q0+RSession.raw_calls+RSession.sign_calls*signing_budget].
  + proc; rcondt 2; first by auto; rewrite /valid_request; smt().
    wp; exists* (size Independent.queries); elim* => q.
    call (role_grind_public_cost q); auto; smt().
  conseq hcost session_sign_history; rewrite /session_invariant; smt().
qed.

module SessionRun (A : RClient) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    RSession(Independent).init(seed,root,qr,qs);
    A(RSession(Independent)).run(seed,root);
    return RSession.bad;
  }
}.

lemma session_hash_stable q0 qr qs c b :
  hoare[RSession(Independent).hash :
    RSession.raw_limit = qr /\ RSession.sign_limit = qs /\ RSession.sign_calls = c /\ RSession.bad = b /\
    session_invariant q0 qr qs RSession.raw_calls RSession.sign_calls RSession.seed RSession.root
      RSession.contexts RSession.bad Independent.secrethistory Independent.rawhistory Independent.queries ==>
    RSession.raw_limit = qr /\ RSession.sign_limit = qs /\ RSession.sign_calls = c /\ RSession.bad = b /\
    session_invariant q0 qr qs RSession.raw_calls RSession.sign_calls RSession.seed RSession.root
      RSession.contexts RSession.bad Independent.secrethistory Independent.rawhistory Independent.queries].
proof.
  have hcost : hoare[RSession(Independent).hash :
    RSession.raw_limit = qr /\ RSession.sign_limit = qs /\ RSession.sign_calls = c /\ RSession.bad = b /\
    0 <= RSession.raw_calls <= qr /\ 0 <= RSession.sign_calls <= qs /\
    size RSession.seed = 32 /\ size RSession.root = 32 /\
    size Independent.queries <= q0+RSession.raw_calls+RSession.sign_calls*signing_budget ==>
    RSession.raw_limit = qr /\ RSession.sign_limit = qs /\ RSession.sign_calls = c /\ RSession.bad = b /\
    0 <= RSession.raw_calls <= qr /\ 0 <= RSession.sign_calls <= qs /\
    size RSession.seed = 32 /\ size RSession.root = 32 /\
    size Independent.queries <= q0+RSession.raw_calls+RSession.sign_calls*signing_budget].
  + proc; sp 1; if; last by auto.
    wp; exists* (size Independent.queries); elim* => q.
    call (independent_hash_count q); auto; smt().
  conseq hcost session_hash_history; rewrite /session_invariant; smt().
qed.

lemma adaptive_session_exhaustion (A <: RClient {-RSession,-Independent}) q0 qr qs seed root &m :
  0 <= q0 => 0 <= qr => 0 <= qs => size seed = 32 => size root = 32 =>
  size Independent.queries{m} <= q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  no_r_tails Independent.secrethistory{m} =>
  Pr[SessionRun(A).run(seed,root,qr,qs) @ &m : RSession.bad] <=
    bigi predT (fun _ => exhaustion_charge (q0+qr+qs*signing_budget)) 0 qs.
proof.
  move=> hq hqr hqs hs hr hsize hrecord hnor.
  fel 1 RSession.sign_calls (fun _ => exhaustion_charge (q0+qr+qs*signing_budget)) qs RSession.bad
    [RSession(Independent).sign : (valid_request random message /\ RSession.sign_calls < RSession.sign_limit);
     RSession(Independent).hash : false]
    (RSession.raw_limit = qr /\ RSession.sign_limit = qs /\
      session_invariant q0 qr qs RSession.raw_calls RSession.sign_calls RSession.seed RSession.root
        RSession.contexts RSession.bad Independent.secrethistory Independent.rawhistory Independent.queries) => //.
  + rewrite /session_invariant; smt().
  + inline RSession(Independent).init; auto; rewrite /session_invariant /session_history /r_history_contexts
      /ContextExhaustion.accepted_contexts /no_r_tails /=; smt().
  + move=> b c; conseq (session_hash_stable q0 qr qs c b); smt().
  + conseq (session_bad_step q0 qr qs); smt().
  + move=> c; conseq (session_sign_progress q0 qr qs c); smt().
  move=> b c; proc; rcondf 2; by auto; rewrite /valid_request; smt().
qed.
