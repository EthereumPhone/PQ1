(* External Q2 research: history invariants for the deployed-byte game model. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal.
require import RawTrial RTailMessages KeygenPrefixes KeygenExhaustion PreparedHistory.
require import FullSession FullMessageHistory SignerRecorded VerifierHistory MessageHistory.
require import FullHistory ByteSession.

lemma byte_client_history (A <: ByteClient {-FullSession,-Independent}) :
  hoare[A(ByteView(FullSession(Independent))).run :
    full_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.signed_messages FullSession.failed ==>
    full_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.signed_messages FullSession.failed].
proof.
  proc (full_history Independent.secrethistory Independent.rawhistory Independent.queries
    FullSession.signed_messages FullSession.failed) => //.
  + conseq full_hash_recorded full_hash_messages; rewrite /full_history; smt().
  proc; sp 1; if; last by auto.
  wp; call (_ : full_history Independent.secrethistory Independent.rawhistory Independent.queries
    FullSession.signed_messages FullSession.failed ==>
    full_history Independent.secrethistory Independent.rawhistory Independent.queries
    FullSession.signed_messages FullSession.failed).
  + conseq full_sign_recorded full_sign_messages; rewrite /full_history; smt().
  auto.
qed.

lemma byte_driver_history (A <: ByteClient {-FullSession,-Independent}) :
  hoare[ByteDriver(A,Independent).run :
    no_r_tails Independent.secrethistory /\
    history_recorded Independent.rawhistory Independent.queries ==>
    full_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.signed_messages FullSession.failed].
proof.
  proc; seq 2 : (full_history Independent.secrethistory Independent.rawhistory Independent.queries
    FullSession.signed_messages FullSession.failed).
  + call (byte_client_history A); inline FullSession(Independent).init;
      auto; rewrite /full_history; smt(no_r_messages).
  sp 1; if; last by auto.
  exists* FullSession.signed_messages; elim* => messages.
  call (signer_verify_history messages); auto; rewrite /full_history; smt().
qed.

lemma byte_context_history (A <: ByteClient {-FullSession,-Independent}) :
  hoare[ByteContext(A,Independent).run :
    no_r_tails Independent.secrethistory /\
    history_recorded Independent.rawhistory Independent.queries ==>
    full_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.signed_messages FullSession.failed].
proof.
  proc; call (byte_driver_history A).
  call (preparation_preserves_history KeygenPreparation); auto.
qed.

lemma byte_game_history (A <: ByteClient {-FullSession,-Independent}) :
  hoare[IndependentGame(ByteContext(A)).run : true ==>
    full_history Independent.secrethistory Independent.rawhistory Independent.queries
      FullSession.signed_messages FullSession.failed].
proof.
  proc; call (byte_context_history A); inline Independent.init;
    auto; rewrite /no_r_tails /history_recorded; smt(mem_empty).
qed.
