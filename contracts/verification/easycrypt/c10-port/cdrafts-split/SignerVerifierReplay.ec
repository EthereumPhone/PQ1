(* The actual verifier replays a retained complete signature to the prior root. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawLayer RawSigner.
require import PersistentGrind AcceptedContexts FixedHashReplay ForestOpening LayerSignOpening LayerOpeningReplay.
require import SignerCoordinates SignerLayerTrace SignerFinishState SignerRecoveryStep.

lemma raw_verify_trace seed0 root0 message0 (sig0 : raw_signature) digest0 values s0 h0 :
  hoare [RawSigner(Independent).verify :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ accept_digest digest0 /\
    h0.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some digest0 /\
    forest_opening h0 seed0 (hypertree_index digest0) digest0 sig0.`2 sig0.`3 (nth [] values 0) /\
    signer_layer_trace h0 s0 seed0 (hypertree_index digest0) sig0.`4 values 2 /\ nth [] values 2=root0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==> res].
proof.
  proc; seq 1 : (seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ digest=digest0 /\ accept_digest digest0 /\
    forest_opening h0 seed0 (hypertree_index digest0) digest0 sig0.`2 sig0.`3 (nth [] values 0) /\
    signer_layer_trace h0 s0 seed0 (hypertree_index digest0) sig0.`4 values 2 /\ nth [] values 2=root0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + call (hash_from_history (hmsg_input seed0 (pad root0) (pad sig0.`1) message0) digest0 s0 h0); auto; smt().
  sp 1; if; last by auto.
  wp; while (seed=seed0 /\ root=pad root0 /\ sig=sig0 /\ digest=digest0 /\ ht=hypertree_index digest0 /\
    0<=layer<=2 /\ idx_tree=signer_tree ht layer /\ current=nth [] values layer /\
    signer_layer_trace h0 s0 seed0 (hypertree_index digest0) sig0.`4 values 2 /\ nth [] values 2=root0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + exists* layer; elim* => k.
    wp; call (layer_replay_history seed0 k (signer_tree (hypertree_index digest0) (k+1))
      (signer_tree (hypertree_index digest0) k %%512) (nth [] values k)
      (nth ([],0,[]) sig0.`4 k) (nth [] values (k+1)) s0 h0).
    auto; rewrite /signer_layer_trace;
      smt(hypertree_index_range signer_coordinate_step layer_opening_extends).
  wp; call (forest_replay_history seed0 (hypertree_index digest0) digest0 sig0.`2 sig0.`3 (nth [] values 0) s0 h0).
  auto; rewrite /signer_tree; smt(forest_opening_extends).
qed.

lemma raw_verify_opening seed0 root0 message0 (sig0 : raw_signature) digest0 :
  hoare [RawSigner(Independent).verify :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ accept_digest digest0 /\
    Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some digest0 /\
    signer_finish_opening Independent.rawhistory Independent.secrethistory seed0 digest0 sig0 root0 ==> res].
proof.
  conseq (_ : exists values,
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ accept_digest digest0 /\
    Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some digest0 /\
    forest_opening Independent.rawhistory seed0 (hypertree_index digest0) digest0 sig0.`2 sig0.`3 (nth [] values 0) /\
    signer_layer_trace Independent.rawhistory Independent.secrethistory seed0 (hypertree_index digest0) sig0.`4 values 2 /\
    nth [] values 2=root0 ==> res).
  + rewrite /signer_finish_opening; smt().
  elim* => values.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (raw_verify_trace seed0 root0 message0 sig0 digest0 values s0 h0); smt(extends_refl).
qed.
