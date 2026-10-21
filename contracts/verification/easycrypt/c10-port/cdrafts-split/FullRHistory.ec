(* The complete observed session retains the original live-context and query
   history invariants. Nonce exhaustion implies absorbing session failure. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawTrial FullSession FullHistory.
require import ClassifiedHistory ClassifiedSession RObservedSigner RObservedHistory FullRSession.

op full_r_history secret raw queries seed root failed bad =
  history_recorded raw queries /\
  (!failed => classified_history secret raw seed root) /\ (bad => failed).

lemma full_r_sign_classified :
  hoare[FullRSession(Independent).sign :
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed ==>
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* FullSession.seed, FullSession.root; elim* => seed0 root0.
  call (r_observed_sign_classified seed0 root0); auto; rewrite /live_classified; smt().
qed.

lemma full_r_sign_recorded :
  hoare[FullRSession(Independent).sign :
    history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof.
  proc; sp 1; if; last by auto.
  wp; call r_observed_sign_recorded; auto.
qed.

lemma full_r_sign_live_recorded :
  hoare[FullRSession(Independent).sign :
    history_recorded Independent.rawhistory Independent.queries /\
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed ==>
    history_recorded Independent.rawhistory Independent.queries /\
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed].
proof. conseq full_r_sign_recorded full_r_sign_classified; smt(). qed.

lemma full_r_sign_history :
  hoare[FullRSession(Independent).sign :
    full_r_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.seed FullSession.root FullSession.failed RFailure.bad ==>
    full_r_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.seed FullSession.root FullSession.failed RFailure.bad].
proof.
  conseq full_r_sign_live_recorded (full_r_sign_failure Independent);
    rewrite /full_r_history /live_classified; smt().
qed.

lemma full_r_hash_history :
  hoare[FullRSession(Independent).hash :
    full_r_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.seed FullSession.root FullSession.failed RFailure.bad ==>
    full_r_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.seed FullSession.root FullSession.failed RFailure.bad].
proof.
  conseq full_hash_recorded full_hash_classified;
    rewrite /full_r_history /live_classified; smt().
qed.
