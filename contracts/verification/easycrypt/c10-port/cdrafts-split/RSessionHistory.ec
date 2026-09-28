(* Persistent table and successful-context invariants for adaptive calls. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid RoleGrind.
require import RawTrial RTailContexts RHistoryOps IdealWitness ContextExhaustion AcceptedContexts PersistentGrind RSession.

op session_history secret raw queries contexts seed root bad =
  history_recorded raw queries /\ r_history_contexts secret contexts /\
  (!bad => accepted_contexts secret raw contexts seed root).

lemma hash_history_integrity contexts seed root bad0 :
  hoare[Independent.hash : session_history Independent.secrethistory Independent.rawhistory Independent.queries
    contexts seed root bad0 ==>
    session_history Independent.secrethistory Independent.rawhistory Independent.queries contexts seed root bad0].
proof.
  proc; sp 1; if; auto; rewrite /session_history /history_recorded;
    smt(mem_set mem_rcons accepted_contexts_extend extends_refl extends_insert).
qed.

lemma role_grind_recorded :
  hoare[RoleGrind(Independent).run : history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof.
  proc; while (history_recorded Independent.rawhistory Independent.queries).
  + wp; call recorded_hash; wp; call recorded_derive; auto.
  auto.
qed.

lemma role_context_records contexts random0 message0 :
  hoare[RoleGrind(Independent).run : random = random0 /\ message = message0 /\ size message0 = 32 /\
    r_history_contexts Independent.secrethistory contexts ==>
    r_history_contexts Independent.secrethistory (rcons contexts (random0,message0))].
proof.
  proc; while (random = random0 /\ message = message0 /\ size message0 = 32 /\
    r_history_contexts Independent.secrethistory (rcons contexts (random0,message0))).
  + wp; call (hash_keeps_contexts (rcons contexts (random0,message0))); wp.
    exists* i; elim* => i0.
    call (derive_known_context (rcons contexts (random0,message0)) random0 message0 (U32.insubd i0));
      auto; smt(mem_rcons).
  auto; smt(r_history_enlarge).
qed.

lemma role_history_integrity contexts random0 message0 seed0 root0 bad0 :
  hoare[RoleGrind(Independent).run : random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    size message0 = 32 /\ session_history Independent.secrethistory Independent.rawhistory Independent.queries
      contexts seed0 root0 bad0 ==>
    session_history Independent.secrethistory Independent.rawhistory Independent.queries
      (rcons contexts (random0,message0)) seed0 root0 (bad0 \/ res = None)].
proof.
  have hbase : hoare[RoleGrind(Independent).run : random = random0 /\ message = message0 /\ size message0 = 32 /\
      history_recorded Independent.rawhistory Independent.queries /\
      r_history_contexts Independent.secrethistory contexts ==>
      history_recorded Independent.rawhistory Independent.queries /\
      r_history_contexts Independent.secrethistory (rcons contexts (random0,message0))].
  + conseq role_grind_recorded (role_context_records contexts random0 message0); smt().
  case bad0 => hb.
  + conseq hbase; rewrite /session_history; smt().
  conseq hbase (role_grind_records_context contexts random0 message0 seed0 root0);
    rewrite /session_history; smt().
qed.

lemma session_hash_history :
  hoare[RSession(Independent).hash : session_history Independent.secrethistory Independent.rawhistory Independent.queries
    RSession.contexts RSession.seed RSession.root RSession.bad ==>
    session_history Independent.secrethistory Independent.rawhistory Independent.queries
    RSession.contexts RSession.seed RSession.root RSession.bad].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* RSession.contexts, RSession.seed, RSession.root, RSession.bad;
    elim* => contexts seed root bad0.
  call (hash_history_integrity contexts seed root bad0); auto.
qed.

lemma session_sign_history :
  hoare[RSession(Independent).sign : session_history Independent.secrethistory Independent.rawhistory Independent.queries
    RSession.contexts RSession.seed RSession.root RSession.bad ==>
    session_history Independent.secrethistory Independent.rawhistory Independent.queries
    RSession.contexts RSession.seed RSession.root RSession.bad].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* RSession.contexts, random, message, RSession.seed, RSession.root, RSession.bad;
    elim* => contexts random0 message0 seed root bad0.
  call (role_history_integrity contexts random0 message0 seed root bad0); auto; smt().
qed.
