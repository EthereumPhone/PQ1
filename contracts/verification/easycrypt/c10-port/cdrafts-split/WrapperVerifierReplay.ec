(* Verification of a retained complete honest signature succeeds and changes
   neither oracle table. All actual verification query logging remains present. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawLayer RawSigner.
require import RawChainCached ForestOpening LayerSignOpening SignerCoordinates SignerLayerTrace SignerFinishState.
require import WrapperForestReplay WrapperLayerReplay.

lemma wrapper_verify_trace_tables seed0 root0 message0 (sig0 : raw_signature) digest0 values h0 s0 :
  hoare [RawSigner(Independent).verify :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ accept_digest digest0 /\
    h0.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some digest0 /\
    forest_opening h0 seed0 (hypertree_index digest0) digest0 sig0.`2 sig0.`3 (nth [] values 0) /\
    signer_layer_trace h0 s0 seed0 (hypertree_index digest0) sig0.`4 values 2 /\ nth [] values 2=root0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ res].
proof.
  proc; seq 1 : (seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ digest=digest0 /\ accept_digest digest0 /\
    forest_opening h0 seed0 (hypertree_index digest0) digest0 sig0.`2 sig0.`3 (nth [] values 0) /\
    signer_layer_trace h0 s0 seed0 (hypertree_index digest0) sig0.`4 values 2 /\ nth [] values 2=root0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0).
  + call (hash_existing_entry h0 (hmsg_input seed0 (pad root0) (pad sig0.`1) message0) digest0); auto; smt().
  sp 1; if; last by auto.
  wp; while (seed=seed0 /\ root=pad root0 /\ sig=sig0 /\ digest=digest0 /\ ht=hypertree_index digest0 /\
    0<=layer<=2 /\ idx_tree=signer_tree ht layer /\ current=nth [] values layer /\
    signer_layer_trace h0 s0 seed0 (hypertree_index digest0) sig0.`4 values 2 /\ nth [] values 2=root0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0).
  + exists* layer; elim* => k.
    wp; call (wrapper_layer_opening_tables seed0 k (signer_tree (hypertree_index digest0) (k+1))
      (signer_tree (hypertree_index digest0) k %%512) (nth [] values k)
      (nth ([],0,[]) sig0.`4 k) (nth [] values (k+1)) h0 s0).
    auto; rewrite /signer_layer_trace; smt(hypertree_index_range signer_coordinate_step).
  wp; call (wrapper_forest_opening_tables seed0 (hypertree_index digest0) digest0 sig0.`2 sig0.`3 (nth [] values 0) h0).
  auto; rewrite /signer_tree; smt().
qed.

lemma wrapper_verify_opening_tables seed0 root0 message0 (sig0 : raw_signature) digest0 h0 s0 :
  hoare [RawSigner(Independent).verify :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ accept_digest digest0 /\
    h0.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some digest0 /\
    signer_finish_opening h0 s0 seed0 digest0 sig0 root0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ res].
proof.
  conseq (_ : exists values,
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ accept_digest digest0 /\
    h0.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some digest0 /\
    forest_opening h0 seed0 (hypertree_index digest0) digest0 sig0.`2 sig0.`3 (nth [] values 0) /\
    signer_layer_trace h0 s0 seed0 (hypertree_index digest0) sig0.`4 values 2 /\ nth [] values 2=root0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 ==> _).
  + rewrite /signer_finish_opening; smt().
  elim* => values.
  conseq (wrapper_verify_trace_tables seed0 root0 message0 sig0 digest0 values h0 s0); smt().
qed.

lemma wrapper_verify_opening_total seed0 root0 message0 (sig0 : raw_signature) digest0 h0 s0 :
  phoare [RawSigner(Independent).verify :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ accept_digest digest0 /\
    h0.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some digest0 /\
    signer_finish_opening h0 s0 seed0 digest0 sig0 root0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ res] = 1%r.
proof.
  conseq (signer_verify_lossless Independent independent_hash_ll)
    (wrapper_verify_opening_tables seed0 root0 message0 sig0 digest0 h0 s0); smt().
qed.
