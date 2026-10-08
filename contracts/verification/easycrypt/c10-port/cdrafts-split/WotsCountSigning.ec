(* The actual shuffled signer retains its minimal accepted counter. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawWotsFill.
require import PersistentGrind MonotoneHistory AcceptedContexts WotsCatalogOracle WotsFirstCount.

module type WotsFilling (O : PreparationOracle) = {
  proc fill(seed : raw_input, layer tree kp : int, accepted : digest, shuffle : raw_input) :
    raw_input list { O.hash, O.wots }
}.

lemma wots_filling_extends (F <: WotsFilling {-Independent}) s0 h0 :
  hoare [F(PreparationView(Independent)).fill :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  exact (preparation_wots_extends s0 h0).
qed.

lemma factored_wots_first_count seed0 layer0 tree0 kp0 message0 :
  hoare [RawWotsFill(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 ==>
    res<>None => exists d, first_wots_count Independent.rawhistory seed0 layer0 tree0 kp0 message0
      (oget res).`2 d].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    (accepted<>None => first_wots_count Independent.rawhistory seed0 layer0 tree0 kp0 message0
      (oget accepted).`1 (oget accepted).`2)).
  + call (raw_count_first seed0 layer0 tree0 kp0 message0); auto.
  sp 1; if; last by auto.
  exists* accepted,Independent.rawhistory,Independent.secrethistory; elim* => acc h0 s0.
  wp; call (wots_filling_extends RawWotsFill s0 h0); auto;
    smt(extends_refl first_wots_count_extends).
qed.

lemma raw_wots_first_count seed0 layer0 tree0 kp0 message0 :
  hoare [RawWots(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 ==>
    res<>None => exists d, first_wots_count Independent.rawhistory seed0 layer0 tree0 kp0 message0
      (oget res).`2 d].
proof.
  conseq (raw_wots_fill_projection (PreparationView(Independent)))
    (factored_wots_first_count seed0 layer0 tree0 kp0 message0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},kp{m},message{m},shuffle{m}); smt().
  smt().
qed.

lemma repeated_wots_counts h h' seed layer tree kp message c d c' d' :
  extends h h' => first_wots_count h seed layer tree kp message c d =>
  first_wots_count h' seed layer tree kp message c' d' => c=c' /\ d=d'.
proof. smt(first_wots_count_extends first_wots_count_unique). qed.
