(* External Q2 research: complete signing preserves the fresh-or-repeated
   classification whenever it returns a signature. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RoleGrind RawSigner.
require import PreparedFinish ClassifiedHistory ClassifiedGrind.

lemma wots_keeps_classified seed0 root0 :
  hoare[PreparationView(Independent).wots :
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0 ==>
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0].
proof. proc; call (derive_nonr_classified seed0 root0); auto; rewrite /wots_tag /=. qed.

lemma fors_keeps_classified seed0 root0 :
  hoare[PreparationView(Independent).fors :
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0 ==>
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0].
proof. proc; call (derive_nonr_classified seed0 root0); auto; rewrite /fors_tag /=. qed.

lemma preparation_keeps_classified (P <: Preparation {-Independent}) seed0 root0 :
  hoare[P(PreparationView(Independent)).run :
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0 ==>
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0].
proof.
  proc (classified_history Independent.secrethistory Independent.rawhistory seed0 root0) => //.
  + exact (hash_keeps_classified seed0 root0).
  + exact (wots_keeps_classified seed0 root0).
  exact (fors_keeps_classified seed0 root0).
qed.

lemma finisher_classified (F <: PreparationFinisher {-Independent}) seed0 root0 :
  hoare[F(PreparationView(Independent)).finish :
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0 ==>
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0].
proof.
  proc (classified_history Independent.secrethistory Independent.rawhistory seed0 root0) => //.
  + exact (hash_keeps_classified seed0 root0).
  + exact (wots_keeps_classified seed0 root0).
  exact (fors_keeps_classified seed0 root0).
qed.

lemma signer_finish_classified seed0 root0 :
  hoare[RawSigner(Independent).finish :
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0 ==>
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0].
proof.
  conseq (prepared_finish_refines Independent) (finisher_classified PreparedFinish seed0 root0).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},randomizer{m},digest{m},shuffle{m}).
    smt().
  smt().
qed.

lemma signer_sign_classified seed0 root0 :
  hoare[RawSigner(Independent).sign :
    seed = seed0 /\ root = root0 /\ size message = 32 /\
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0 ==>
    res <> None => classified_history Independent.secrethistory Independent.rawhistory seed0 root0].
proof.
  proc; exists* random, message; elim* => random0 message0.
  seq 1 : (accepted <> None =>
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0).
  + call (role_grind_classifies seed0 root0 random0 message0); auto.
  sp 1; if; last by auto.
  call (signer_finish_classified seed0 root0); auto; smt().
qed.
