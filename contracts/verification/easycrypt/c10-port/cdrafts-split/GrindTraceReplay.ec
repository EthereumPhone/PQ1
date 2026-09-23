(* External Q2 research: repeated contexts cannot create a different accepted
   digest; intervening public/private computations preserve the first trace. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind C10HashDomains C10Counter PrefixGuess PrefixHybrid RoleGrind.
require import PersistentGrind AcceptedContexts GrindTrace GrindTraceRecorded.
require import IdealWitness RTailFresh.

lemma hash_keeps_trace random0 message0 seed0 root0 answer :
  hoare[Independent.hash :
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer ==>
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer].
proof.
  proc; sp 1; if; auto; smt(completed_trace_extends extends_refl extends_insert).
qed.

lemma derive_keeps_trace random0 message0 seed0 root0 answer :
  hoare[Independent.derive :
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer ==>
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer].
proof.
  proc; if; auto; smt(completed_trace_extends extends_refl extends_insert).
qed.

lemma context_keeps_trace (A <: PrefixContext {-Independent}) random0 message0 seed0 root0 answer :
  hoare[A(Independent).run :
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer ==>
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer].
proof.
  proc (completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer) => //.
  + exact (hash_keeps_trace random0 message0 seed0 root0 answer).
  exact (derive_keeps_trace random0 message0 seed0 root0 answer).
qed.

lemma role_grind_keeps_trace random0 message0 seed0 root0 answer :
  hoare[RoleGrind(Independent).run :
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer ==>
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer].
proof.
  proc; while (completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer).
  + wp; call (hash_keeps_trace random0 message0 seed0 root0 answer); wp.
    call (derive_keeps_trace random0 message0 seed0 root0 answer); auto.
  auto.
qed.

lemma role_grind_repeated_output random0 message0 seed0 root0 answer :
  hoare[RoleGrind(Independent).run :
    random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer ==>
    res <> None => oget res = answer].
proof.
  conseq (role_grind_records_trace random0 message0 seed0 root0)
    (role_grind_keeps_trace random0 message0 seed0 root0 answer); smt(completed_trace_unique).
qed.

lemma completed_trace_witness s h random message seed root answer :
  completed_trace s h random message seed root answer =>
  ideal_witness s h random message seed root.
proof.
  rewrite /completed_trace => hex.
  elim hex => j [#] hj hb hp ht ha he.
  rewrite /ideal_witness.
  exists j (oget s.[r_tail random message (U32.insubd j)])
    (trial_digest s h random message seed root j).
  move: ht; rewrite /trial_recorded /trial_digest /trial_input /trial_random /r_query.
  smt(domE).
qed.

lemma repeated_grind_failure_zero random message seed root answer &m :
  completed_trace Independent.secrethistory{m} Independent.rawhistory{m} random message seed root answer =>
  Pr[RoleGrind(Independent).run(random,message,seed,root) @ &m : res = None] = 0%r.
proof.
  move=> ht; apply ideal_witness_failure_zero.
  exact (completed_trace_witness _ _ _ _ _ _ _ ht).
qed.

lemma repeated_grind_other_event_zero p random0 message0 seed0 root0 answer &m :
  completed_trace Independent.secrethistory{m} Independent.rawhistory{m} random0 message0 seed0 root0 answer =>
  !p answer =>
  Pr[RoleGrind(Independent).run(random0,message0,seed0,root0) @ &m : res <> None /\ p (oget res)] = 0%r.
proof.
  move=> ht hp.
  byphoare (_ : random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer ==>
    res <> None /\ p (oget res)) => //.
  hoare; conseq (role_grind_repeated_output random0 message0 seed0 root0 answer); smt().
qed.
