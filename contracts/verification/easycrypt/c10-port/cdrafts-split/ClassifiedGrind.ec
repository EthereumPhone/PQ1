(* External Q2 research: the actual grinder completes the pending context
   while preserving every other context's freshness or completed trace. *)
require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid RoleGrind.
require import GrindTrace GrindTraceRecorded ClassifiedHistory.

lemma hash_keeps_classified seed0 root0 :
  hoare[Independent.hash :
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0 ==>
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0].
proof. proc; sp 1; if; auto; rewrite /classified_history; smt(classified_raw_insert). qed.

lemma hash_keeps_classified_except seed0 root0 random0 message0 :
  hoare[Independent.hash :
    classified_except Independent.secrethistory Independent.rawhistory seed0 root0 random0 message0 ==>
    classified_except Independent.secrethistory Independent.rawhistory seed0 root0 random0 message0].
proof. proc; sp 1; if; auto; rewrite /classified_except; smt(classified_raw_insert). qed.

lemma derive_keeps_classified_except seed0 root0 random0 message0 nonce :
  hoare[Independent.derive :
    classified_except Independent.secrethistory Independent.rawhistory seed0 root0 random0 message0 /\
    size message0 = 32 /\ tail = r_tail random0 message0 nonce ==>
    classified_except Independent.secrethistory Independent.rawhistory seed0 root0 random0 message0].
proof. proc; if; auto; rewrite /classified_except; smt(classified_other_insert). qed.

lemma derive_nonr_classified seed0 root0 :
  hoare[Independent.derive :
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0 /\
    head 0 tail <> 82 ==>
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0].
proof. proc; if; auto; rewrite /classified_history; smt(classified_nonr_insert). qed.

lemma role_grind_classified_except seed0 root0 random0 message0 :
  hoare[RoleGrind(Independent).run :
    random = random0 /\ message = message0 /\ size message0 = 32 /\
    classified_except Independent.secrethistory Independent.rawhistory seed0 root0 random0 message0 ==>
    classified_except Independent.secrethistory Independent.rawhistory seed0 root0 random0 message0].
proof.
  proc; while (random = random0 /\ message = message0 /\ size message0 = 32 /\
    classified_except Independent.secrethistory Independent.rawhistory seed0 root0 random0 message0).
  + wp; call (hash_keeps_classified_except seed0 root0 random0 message0); wp.
    exists* i; elim* => i0.
    call (derive_keeps_classified_except seed0 root0 random0 message0 (U32.insubd i0)); auto.
  auto.
qed.

lemma role_grind_classifies seed0 root0 random0 message0 :
  hoare[RoleGrind(Independent).run :
    seed = seed0 /\ root = root0 /\ random = random0 /\ message = message0 /\ size message0 = 32 /\
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0 ==>
    res <> None => classified_history Independent.secrethistory Independent.rawhistory seed0 root0].
proof.
  conseq (role_grind_classified_except seed0 root0 random0 message0)
    (role_grind_records_trace random0 message0 seed0 root0);
    smt(classified_exclude classified_include).
qed.
