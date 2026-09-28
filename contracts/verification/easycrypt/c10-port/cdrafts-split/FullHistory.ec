(* External Q2 research: initialize and preserve the complete adaptive history. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal.
require import RawTrial RTailMessages KeygenPrefixes KeygenExhaustion PreparedHistory.
require import RawSigner FullSession FullMessageHistory SignerRecorded VerifierHistory MessageHistory.

op full_history secret raw queries messages failed =
  history_recorded raw queries /\ (!failed => r_history_messages secret messages).

lemma full_hash_recorded :
  hoare[FullSession(Independent).hash :
    history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof. proc; sp 1; if; last by auto.
  wp; call recorded_hash; auto. qed.

lemma full_sign_recorded :
  hoare[FullSession(Independent).sign :
    history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof. proc; sp 1; if; last by auto.
  wp; call signer_sign_recorded; auto. qed.

lemma full_client_recorded (A <: FullClient {-FullSession,-Independent}) :
  hoare[A(FullSession(Independent)).run :
    history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof.
  proc (history_recorded Independent.rawhistory Independent.queries) => //.
  + exact full_hash_recorded.
  exact full_sign_recorded.
qed.

lemma full_client_history (A <: FullClient {-FullSession,-Independent}) :
  hoare[A(FullSession(Independent)).run :
    full_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.signed_messages FullSession.failed ==>
    full_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.signed_messages FullSession.failed].
proof.
  conseq (full_client_recorded A) (full_client_messages A); rewrite /full_history; smt().
qed.

lemma signer_verify_history messages :
  hoare[RawSigner(Independent).verify :
    history_recorded Independent.rawhistory Independent.queries /\
    r_history_messages Independent.secrethistory messages ==>
    history_recorded Independent.rawhistory Independent.queries /\
    r_history_messages Independent.secrethistory messages].
proof. conseq signer_verify_recorded (signer_verify_messages messages); smt(). qed.

lemma full_driver_history (A <: FullClient {-FullSession,-Independent}) :
  hoare[FullDriver(A,Independent).run :
    no_r_tails Independent.secrethistory /\
    history_recorded Independent.rawhistory Independent.queries ==>
    full_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.signed_messages FullSession.failed].
proof.
  proc; seq 2 : (full_history Independent.secrethistory Independent.rawhistory Independent.queries
    FullSession.signed_messages FullSession.failed).
  + call (full_client_history A); inline FullSession(Independent).init;
      auto; rewrite /full_history; smt(no_r_messages).
  sp 1; if; last by auto.
  exists* FullSession.signed_messages; elim* => messages.
  call (signer_verify_history messages); auto; rewrite /full_history; smt().
qed.

lemma full_context_history (A <: FullClient {-FullSession,-Independent}) :
  hoare[FullContext(A,Independent).run :
    no_r_tails Independent.secrethistory /\
    history_recorded Independent.rawhistory Independent.queries ==>
    full_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.signed_messages FullSession.failed].
proof.
  proc; call (full_driver_history A).
  call (preparation_preserves_history KeygenPreparation); auto.
qed.

lemma full_game_history (A <: FullClient {-FullSession,-Independent}) :
  hoare[IndependentGame(FullContext(A)).run : true ==>
    full_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.signed_messages FullSession.failed].
proof.
  proc; call (full_context_history A); inline Independent.init;
    auto; rewrite /no_r_tails /history_recorded; smt(mem_empty).
qed.
