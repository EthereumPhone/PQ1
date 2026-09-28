(* Exact two-layer recovery links, observed in the unchanged verifier. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawForest RawLayer RawSigner RawSignature RawCountRecorded.
require import PersistentGrind AcceptedContexts SignerCoordinates SignerComponentHistory LayerRecoveryRecord.

op verifier_layer_records h seed d (sig : raw_signature) root =
  exists forest lower,
    layer_recovery_record h seed 0 (hypertree_index d %/512) (hypertree_index d %%512)
      forest (nth ([],0,[]) sig.`4 0) lower /\
    layer_recovery_record h seed 1 0 (hypertree_index d %/512)
      lower (nth ([],0,[]) sig.`4 1) root.

op verified_layer_records h seed root message (sig : raw_signature) =
  exists d, accept_digest d /\ h.[hmsg_input seed (pad root) (pad sig.`1) message]=Some d /\
    verifier_layer_records h seed d sig root.

lemma verifier_records_join h h' seed d (sig : raw_signature) forest lower root :
  extends h h' =>
  layer_recovery_record h seed 0 (hypertree_index d %/512) (hypertree_index d %%512)
    forest (nth ([],0,[]) sig.`4 0) lower =>
  layer_recovery_record h' seed 1 0 (hypertree_index d %/512)
    lower (nth ([],0,[]) sig.`4 1) root =>
  verifier_layer_records h' seed d sig root.
proof.
  move=> hh hb ht; exists forest lower; smt(layer_record_extends).
qed.

lemma verifier_records_layers seed0 root0 message0 (sig0 : raw_signature) :
  hoare [RawSigner(Independent).verify :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ signature_width sig0 ==>
    res => verified_layer_records Independent.rawhistory seed0 root0 message0 sig0].
proof.
  proc; seq 1 : (seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ signature_width sig0 /\
    Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some digest).
  + call (hash_records_input (hmsg_input seed0 (pad root0) (pad sig0.`1) message0)); auto.
  exists* digest,Independent.rawhistory,Independent.secrethistory; elim* => d0 hstart sstart.
  sp 1; if; last auto.
  seq 2 : (seed=seed0 /\ root=pad root0 /\ sig=sig0 /\ signature_width sig0 /\
    digest=d0 /\ accept_digest d0 /\ ht=hypertree_index d0 /\
    hstart.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some d0 /\
    extends sstart Independent.secrethistory /\ extends hstart Independent.rawhistory).
  + call (forest_recovery_extends RawForest sstart hstart); auto; smt(extends_refl).
  exists* current; elim* => forest0.
  wp; while (seed=seed0 /\ root=pad root0 /\ sig=sig0 /\ signature_width sig0 /\
    digest=d0 /\ accept_digest d0 /\ ht=hypertree_index d0 /\ 0<=layer<=2 /\
    idx_tree=signer_tree ht layer /\
    hstart.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some d0 /\
    extends sstart Independent.secrethistory /\ extends hstart Independent.rawhistory /\
    (layer=0 => current=forest0) /\
    (layer=1 => layer_recovery_record Independent.rawhistory seed0 0
      (hypertree_index d0 %/512) (hypertree_index d0 %%512) forest0 (nth ([],0,[]) sig0.`4 0) current) /\
    (layer=2 => verifier_layer_records Independent.rawhistory seed0 d0 sig0 current)).
  + exists* layer,current,Independent.rawhistory,Independent.secrethistory; elim* => k cur h0 s0.
    case (k=0).
    - wp; call (layer_record_with_history seed0 0 (hypertree_index d0 %/512)
        (hypertree_index d0 %%512) forest0 (nth ([],0,[]) sig0.`4 0) s0 h0).
      auto; rewrite /signature_width /layer_width /rows_width /signer_tree /extends;
        smt(extends_refl hypertree_index_range allP mem_nth pdiv_small modz_small divz_ge0 ltz_divLR).
    wp; call (layer_record_with_history seed0 1 0
      (hypertree_index d0 %/512) cur (nth ([],0,[]) sig0.`4 1) s0 h0).
    auto; rewrite /signature_width /layer_width /rows_width /signer_tree /extends;
      smt(extends_refl verifier_records_join hypertree_index_range
        allP mem_nth pdiv_small modz_small divz_ge0 ltz_divLR).
  auto; rewrite /signer_tree /verified_layer_records /verifier_layer_records /pad /extends;
    smt(catIs).
qed.
