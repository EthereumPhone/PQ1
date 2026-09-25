(* The actual recovered forest is the message consumed by the lower WOTS layer. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawForest RawLayer RawSigner RawSignature RawCountRecorded.
require import PersistentGrind AcceptedContexts SignerCoordinates SignerComponentHistory.
require import ForestOpening ForestRecoveryRecord LayerRecoveryRecord.

op verifier_forest_records h seed d (sig : raw_signature) root =
  exists forest lower,
    forest_opening h seed (hypertree_index d) d sig.`2 sig.`3 forest /\
    layer_recovery_record h seed 0 (hypertree_index d %/512) (hypertree_index d %%512)
      forest (nth ([],0,[]) sig.`4 0) lower /\
    layer_recovery_record h seed 1 0 (hypertree_index d %/512)
      lower (nth ([],0,[]) sig.`4 1) root.

op verified_forest_records h seed root message (sig : raw_signature) =
  exists d, accept_digest d /\ h.[hmsg_input seed (pad root) (pad sig.`1) message]=Some d /\
    verifier_forest_records h seed d sig root.

lemma verifier_forest_records_join h h' seed d (sig : raw_signature) forest lower root :
  extends h h' =>
  forest_opening h seed (hypertree_index d) d sig.`2 sig.`3 forest =>
  layer_recovery_record h seed 0 (hypertree_index d %/512) (hypertree_index d %%512)
    forest (nth ([],0,[]) sig.`4 0) lower =>
  layer_recovery_record h' seed 1 0 (hypertree_index d %/512)
    lower (nth ([],0,[]) sig.`4 1) root =>
  verifier_forest_records h' seed d sig root.
proof.
  move=> hh hf hb ht; exists forest lower; smt(forest_opening_extends layer_record_extends).
qed.

lemma forest_record_with_history seed0 ht0 digest0 secrets0 auths0 s0 h0 :
  hoare [RawForest(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    size secrets0=13 /\ size auths0=12 /\ all (fun p => size p=11) auths0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    forest_opening Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 res /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  conseq (raw_forest_recovery_recorded seed0 ht0 digest0 secrets0 auths0)
    (forest_recovery_extends RawForest s0 h0); smt().
qed.

lemma verifier_records_forest seed0 root0 message0 (sig0 : raw_signature) :
  hoare [RawSigner(Independent).verify :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ signature_width sig0 ==>
    res => verified_forest_records Independent.rawhistory seed0 root0 message0 sig0].
proof.
  proc; seq 1 : (seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ signature_width sig0 /\
    Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some digest).
  + call (hash_records_input (hmsg_input seed0 (pad root0) (pad sig0.`1) message0)); auto.
  exists* digest,Independent.rawhistory,Independent.secrethistory; elim* => d0 hstart sstart.
  sp 1; if; last auto.
  seq 2 : (seed=seed0 /\ root=pad root0 /\ sig=sig0 /\ signature_width sig0 /\
    digest=d0 /\ accept_digest d0 /\ ht=hypertree_index d0 /\
    hstart.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some d0 /\
    extends sstart Independent.secrethistory /\ extends hstart Independent.rawhistory /\
    forest_opening Independent.rawhistory seed0 (hypertree_index d0) d0 sig0.`2 sig0.`3 current).
  + call (forest_record_with_history seed0 (hypertree_index d0) d0 sig0.`2 sig0.`3 sstart hstart).
    auto; rewrite /signature_width /rows_width; smt(extends_refl allP).
  exists* current; elim* => forest0.
  wp; while (seed=seed0 /\ root=pad root0 /\ sig=sig0 /\ signature_width sig0 /\
    digest=d0 /\ accept_digest d0 /\ ht=hypertree_index d0 /\ 0<=layer<=2 /\
    idx_tree=signer_tree ht layer /\
    hstart.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some d0 /\
    extends sstart Independent.secrethistory /\ extends hstart Independent.rawhistory /\
    forest_opening Independent.rawhistory seed0 (hypertree_index d0) d0 sig0.`2 sig0.`3 forest0 /\
    (layer=0 => current=forest0) /\
    (layer=1 => layer_recovery_record Independent.rawhistory seed0 0
      (hypertree_index d0 %/512) (hypertree_index d0 %%512) forest0 (nth ([],0,[]) sig0.`4 0) current) /\
    (layer=2 => verifier_forest_records Independent.rawhistory seed0 d0 sig0 current)).
  + exists* layer,current,Independent.rawhistory,Independent.secrethistory; elim* => k cur h0 s0.
    case (k=0).
    - wp; call (layer_record_with_history seed0 0 (hypertree_index d0 %/512)
        (hypertree_index d0 %%512) forest0 (nth ([],0,[]) sig0.`4 0) s0 h0).
      auto; rewrite /signature_width /layer_width /rows_width /signer_tree /extends;
        smt(extends_refl forest_opening_extends hypertree_index_range allP mem_nth pdiv_small modz_small divz_ge0 ltz_divLR).
    wp; call (layer_record_with_history seed0 1 0
      (hypertree_index d0 %/512) cur (nth ([],0,[]) sig0.`4 1) s0 h0).
    auto; rewrite /signature_width /layer_width /rows_width /signer_tree /extends;
      smt(extends_refl forest_opening_extends verifier_forest_records_join hypertree_index_range
        allP mem_nth pdiv_small modz_small divz_ge0 ltz_divLR).
  auto; rewrite /signer_tree /verified_forest_records /verifier_forest_records /pad /extends;
    smt(catIs).
qed.
