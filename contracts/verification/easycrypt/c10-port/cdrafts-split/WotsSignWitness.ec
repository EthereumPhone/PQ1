(* Actual accepted signatures retain a concrete reference opening witness. *)
require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind AcceptedContexts RawCountRecorded WotsReference WotsReferenceRoot.
require import WotsSignatureValue RawWotsFill WotsFillCorrect WotsCountWitness.

op wots_opening h s seed layer tree kp message root (signature : raw_input list * int) =
  wots_root h s seed layer tree kp root /\ 0<=signature.`2<signing_budget /\
  exists d, count_accepts d /\
    h.[wots_count_input seed layer tree kp message signature.`2]=Some d /\
    wots_signature h s seed layer tree kp d signature.`1.

lemma factored_wots_sign_witness seed0 layer0 tree0 kp0 message0 root0 :
  hoare [RawWotsFill(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 ==>
    res<>None => exists h s,
      wots_opening h s seed0 layer0 tree0 kp0 message0 root0 (oget res) /\
      extends s Independent.secrethistory /\ extends h Independent.rawhistory].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 /\
    (accepted<>None => 0 <= (oget accepted).`1 < signing_budget /\ count_accepts (oget accepted).`2 /\
      Independent.rawhistory.[wots_count_input seed0 layer0 tree0 kp0 message0 (oget accepted).`1]
        = Some (oget accepted).`2)).
  + call (count_retains_wots_witness seed0 layer0 tree0 kp0 message0 root0); auto.
  sp 1; if; last by auto.
  exists* accepted,Independent.rawhistory,Independent.secrethistory; elim* => acc h0 s0.
  wp; call (wots_fill_correct seed0 layer0 tree0 kp0 (oget acc).`2 h0 s0).
  auto; rewrite /wots_opening /wots_root; smt(extends_refl).
qed.

lemma raw_wots_sign_witness seed0 layer0 tree0 kp0 message0 root0 :
  hoare [RawWots(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 ==>
    res<>None => exists h s,
      wots_opening h s seed0 layer0 tree0 kp0 message0 root0 (oget res) /\
      extends s Independent.secrethistory /\ extends h Independent.rawhistory].
proof.
  conseq (raw_wots_fill_projection (PreparationView(Independent)))
    (factored_wots_sign_witness seed0 layer0 tree0 kp0 message0 root0).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},kp{m},message{m},shuffle{m}); smt().
  smt().
qed.
