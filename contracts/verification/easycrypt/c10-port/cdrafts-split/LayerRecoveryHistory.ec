(* Actual layer recovery retains the signing witness and the recorded path. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawLayer.
require import PersistentGrind MonotoneHistory LayerPath WotsSignWitness LayerRecoveryCorrect.

module type LayerRecovery (O : PreparationOracle) = {
  proc recover(seed : raw_input, layer tree leaf : int, message : raw_input,
    sig : layer_signature) : raw_input { O.hash }
}.

lemma hash_keeps_layer_history seed0 layer0 tree0 index0 leaf0 auth0 root0 s0 h0 :
  hoare [Independent.hash :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0 ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0].
proof.
  conseq (independent_hash_extends s0 h0)
    (hash_keeps_layer_path seed0 layer0 tree0 index0 leaf0 auth0 root0); smt().
qed.

lemma layer_recovery_keeps_history (R <: LayerRecovery {-Independent}) seed0 layer0 tree0 index0 leaf0 auth0 root0 s0 h0 :
  hoare [R(PreparationView(Independent)).recover :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0 ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0) => //.
  exact (hash_keeps_layer_history seed0 layer0 tree0 index0 leaf0 auth0 root0 s0 h0).
qed.

lemma layer_recovers_opening_persistent seed0 layer0 tree0 index0 message0 (sig0 : layer_signature) leaf0 root0 h0 s0 :
  hoare [RawLayer(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ sig=sig0 /\
    wots_opening h0 s0 seed0 layer0 tree0 index0 message0 leaf0 (sig0.`1,sig0.`2) /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 sig0.`3 root0 ==>
    res=root0 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 sig0.`3 root0].
proof.
  conseq (layer_recovers_opening seed0 layer0 tree0 index0 message0 sig0 leaf0 root0 h0 s0)
    (layer_recovery_keeps_history RawLayer seed0 layer0 tree0 index0 leaf0 sig0.`3 root0 s0 h0); smt().
qed.
