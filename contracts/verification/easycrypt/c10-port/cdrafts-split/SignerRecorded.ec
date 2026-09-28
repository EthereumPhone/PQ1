(* External Q2 research: complete signing retains the public-query census. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawSigner PreparedFinish RawTrial PreparedHistory RSessionHistory.

lemma prepared_finisher_recorded (F <: PreparationFinisher {-Independent}) :
  hoare[F(PreparationView(Independent)).finish :
    history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof.
  proc (history_recorded Independent.rawhistory Independent.queries) => //.
  + exact (recorded_hash ).
  + exact (wots_preserves_recorded).
  exact (fors_preserves_recorded).
qed.

lemma prepared_finish_recorded :
  hoare[PreparedFinish(PreparationView(Independent)).finish :
    history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof. exact (prepared_finisher_recorded PreparedFinish). qed.

lemma signer_finish_recorded :
  hoare[RawSigner(Independent).finish :
    history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof.
  conseq (prepared_finish_refines Independent) (prepared_finish_recorded).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},randomizer{m},digest{m},shuffle{m}).
    smt().
  smt().
qed.


lemma signer_sign_recorded :
  hoare[RawSigner(Independent).sign :
    history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof.
  proc; seq 1 : (history_recorded Independent.rawhistory Independent.queries).
  + call role_grind_recorded; auto.
  sp 1; if; last by auto.
  call signer_finish_recorded; auto.
qed.
