(* Accepted contexts persist across every oracle call in later signing work. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid RoleGrind.
require import PersistentGrind IdealWitness ContextExhaustion.

lemma extends_refl h : extends h h.
proof. by rewrite /extends. qed.
lemma extends_insert h x y : x \notin h => extends h h.[x <- y].
proof. rewrite /extends; smt(get_setE domE). qed.

lemma accepted_contexts_extend s0 r0 s r contexts seed root :
  extends s0 s => extends r0 r => accepted_contexts s0 r0 contexts seed root =>
  accepted_contexts s r contexts seed root.
proof. rewrite /extends /accepted_contexts /ideal_witness; smt(). qed.

lemma hash_keeps_accepted contexts seed root :
  hoare[Independent.hash : accepted_contexts Independent.secrethistory Independent.rawhistory contexts seed root ==>
    accepted_contexts Independent.secrethistory Independent.rawhistory contexts seed root].
proof.
  proc; sp 1; if; auto; smt(accepted_contexts_extend extends_refl extends_insert).
qed.
lemma derive_keeps_accepted contexts seed root :
  hoare[Independent.derive : accepted_contexts Independent.secrethistory Independent.rawhistory contexts seed root ==>
    accepted_contexts Independent.secrethistory Independent.rawhistory contexts seed root].
proof.
  proc; if; auto; smt(accepted_contexts_extend extends_refl extends_insert).
qed.

lemma role_grind_keeps_accepted contexts seed0 root0 :
  hoare[RoleGrind(Independent).run :
    accepted_contexts Independent.secrethistory Independent.rawhistory contexts seed0 root0 ==>
    accepted_contexts Independent.secrethistory Independent.rawhistory contexts seed0 root0].
proof.
  proc; while (accepted_contexts Independent.secrethistory Independent.rawhistory contexts seed0 root0).
  + wp; call (hash_keeps_accepted contexts seed0 root0); wp.
    call (derive_keeps_accepted contexts seed0 root0); auto.
  auto.
qed.

lemma accepted_contexts_add secret raw contexts seed root random message :
  accepted_contexts secret raw contexts seed root =>
  ideal_witness secret raw random message seed root =>
  accepted_contexts secret raw (rcons contexts (random,message)) seed root.
proof. rewrite /accepted_contexts; smt(mem_rcons). qed.

lemma role_grind_records_context contexts random0 message0 seed0 root0 :
  hoare[RoleGrind(Independent).run : random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    accepted_contexts Independent.secrethistory Independent.rawhistory contexts seed0 root0 ==>
    res <> None => accepted_contexts Independent.secrethistory Independent.rawhistory
      (rcons contexts (random0,message0)) seed0 root0].
proof.
  conseq (role_grind_keeps_accepted contexts seed0 root0)
    (ideal_grind_records random0 message0 seed0 root0); smt(accepted_contexts_add).
qed.
