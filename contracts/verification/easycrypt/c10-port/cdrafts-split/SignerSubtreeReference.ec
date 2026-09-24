(* Successful complete signing records the lower root used as its top message. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawForest RawLayer RawSigner.
require import PersistentGrind AcceptedContexts MerkleRootWitness LayerSignOpening LayerOpeningReplay.
require import SignerCoordinates SignerLayerStep LayerReturnedRoot SignerComponentHistory.

op signed_subtree_reference h s seed ht layers =
  exists lower root, merkle_root_witness h s seed 0 (ht %/512) lower /\
    layer_opening h s seed 1 0 (ht %/512) lower (nth ([],0,[]) layers 1) root.

lemma signed_subtree_extends h h' s s' seed ht layers :
  extends h h' => extends s s' => signed_subtree_reference h s seed ht layers =>
  signed_subtree_reference h' s' seed ht layers.
proof.
  move=> hh hs [lower root [hw ho]]; exists lower root.
  smt(merkle_root_witness_extends layer_opening_extends).
qed.

lemma signed_subtree_step h h' s s' seed ht layers lower signature root :
  extends h h' => extends s s' => size layers=1 =>
  merkle_root_witness h s seed 0 (ht %/512) lower =>
  layer_opening h' s' seed 1 0 (ht %/512) lower signature root =>
  signed_subtree_reference h' s' seed ht (rcons layers signature).
proof.
  move=> hh hs hl hw ho; exists lower root.
  rewrite nth_rcons hl /=; smt(merkle_root_witness_extends).
qed.

lemma layer_sign_root_and_opening seed0 layer0 tree0 index0 message0 s0 h0 :
  hoare [RawLayer(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (res<>None => layer_opening Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 index0 message0 (oget res).`1 (oget res).`2 /\
      merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 (oget res).`2)].
proof.
  conseq (layer_sign_history_opening seed0 layer0 tree0 index0 message0 s0 h0)
    (raw_layer_returns_recorded_root seed0 layer0 tree0 index0 message0); smt().
qed.

lemma finish_records_subtree seed0 digest0 :
  hoare [RawSigner(Independent).finish : seed=seed0 /\ digest=digest0 ==>
    res<>None => signed_subtree_reference Independent.rawhistory Independent.secrethistory
      seed0 (hypertree_index digest0) (oget res).`4].
proof.
  proc; seq 2 : (seed=seed0 /\ digest=digest0 /\ ht=hypertree_index digest0).
  + call (_ : true ==> true); first by trivial.
    auto.
  wp; while (seed=seed0 /\ digest=digest0 /\ ht=hypertree_index digest0 /\
    0<=layer<=2 /\ idx_tree=signer_tree ht layer /\
    (ok => size layers=layer /\
      (layer=1 => merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 0 (ht %/512) current) /\
      (layer=2 => signed_subtree_reference Independent.rawhistory Independent.secrethistory seed0 ht layers))).
  + exists* layer,current,layers,Independent.rawhistory,Independent.secrethistory;
      elim* => k cur layers0 h0 s0.
    wp; call (layer_sign_root_and_opening seed0 k (signer_tree (hypertree_index digest0) (k+1))
      (signer_tree (hypertree_index digest0) k %%512) cur s0 h0).
    auto; rewrite /signer_tree;
      smt(size_rcons signed_subtree_step extends_refl merkle_root_witness_extends hypertree_index_range
        pdiv_small modz_small divz_ge0 ltz_divLR).
  auto; rewrite /signer_tree; smt().
qed.
