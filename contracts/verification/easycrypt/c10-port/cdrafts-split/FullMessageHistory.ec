(* External Q2 research: the actual fail-stop adaptive session accounts for
   every private R derivation by a successfully signed message. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RTailFresh RTailMessages.
require import RawSigner FullSession MessageHistory SignerMessages.

lemma full_hash_messages :
  hoare[FullSession(Independent).hash :
    (!FullSession.failed => r_history_messages Independent.secrethistory FullSession.signed_messages) ==>
    (!FullSession.failed => r_history_messages Independent.secrethistory FullSession.signed_messages)].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* FullSession.failed, FullSession.signed_messages; elim* => failed0 messages.
  case failed0.
  + call (_ : true ==> true); first by trivial.
    auto; smt().
  call (hash_keeps_messages messages); auto; smt().
qed.

lemma full_sign_messages :
  hoare[FullSession(Independent).sign :
    (!FullSession.failed => r_history_messages Independent.secrethistory FullSession.signed_messages) ==>
    (!FullSession.failed => r_history_messages Independent.secrethistory FullSession.signed_messages)].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* FullSession.signed_messages, random, message; elim* => messages random0 message0.
  call (signer_message_records messages random0 message0); auto; smt().
qed.

lemma full_client_messages (A <: FullClient {-FullSession,-Independent}) :
  hoare[A(FullSession(Independent)).run :
    (!FullSession.failed => r_history_messages Independent.secrethistory FullSession.signed_messages) ==>
    (!FullSession.failed => r_history_messages Independent.secrethistory FullSession.signed_messages)].
proof.
  proc (!FullSession.failed => r_history_messages Independent.secrethistory FullSession.signed_messages) => //.
  + exact full_hash_messages.
  exact full_sign_messages.
qed.

lemma full_client_unqueried_fresh (A <: FullClient {-FullSession,-Independent}) :
  hoare[A(FullSession(Independent)).run :
    (!FullSession.failed => r_history_messages Independent.secrethistory FullSession.signed_messages) ==>
    !FullSession.failed =>
      forall random message, size message = 32 =>
        !List.mem FullSession.signed_messages message =>
        future_fresh Independent.secrethistory random message 0].
proof.
  conseq (full_client_messages A); first by smt().
qed.
