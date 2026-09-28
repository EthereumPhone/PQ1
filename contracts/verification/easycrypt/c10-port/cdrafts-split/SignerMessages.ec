(* External Q2 research: complete signatures preserve message attribution. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawSigner RoleGrind PreparedFinish RTailMessages MessageHistory.

lemma prepared_finisher_messages (F <: PreparationFinisher {-Independent}) messages :
  hoare[F(PreparationView(Independent)).finish :
    r_history_messages Independent.secrethistory messages ==>
    r_history_messages Independent.secrethistory messages].
proof.
  proc (r_history_messages Independent.secrethistory messages) => //.
  + exact (hash_keeps_messages messages).
  + exact (wots_keeps_messages messages).
  exact (fors_keeps_messages messages).
qed.

lemma prepared_finish_messages messages :
  hoare[PreparedFinish(PreparationView(Independent)).finish :
    r_history_messages Independent.secrethistory messages ==>
    r_history_messages Independent.secrethistory messages].
proof. exact (prepared_finisher_messages PreparedFinish messages). qed.

lemma signer_finish_messages messages :
  hoare[RawSigner(Independent).finish :
    r_history_messages Independent.secrethistory messages ==>
    r_history_messages Independent.secrethistory messages].
proof.
  conseq (prepared_finish_refines Independent) (prepared_finish_messages messages).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},randomizer{m},digest{m},shuffle{m}).
    smt().
  smt().
qed.

lemma signer_message_records messages random0 message0 :
  hoare[RawSigner(Independent).sign : random = random0 /\ message = message0 /\
    size message0 = 32 /\ r_history_messages Independent.secrethistory messages ==>
    r_history_messages Independent.secrethistory (rcons messages message0)].
proof.
  proc; sp 0; seq 1 : (r_history_messages Independent.secrethistory (rcons messages message0)).
  + call (role_message_records messages random0 message0); auto.
  sp 1; if; last by auto.
  call (signer_finish_messages (rcons messages message0)); auto.
qed.
