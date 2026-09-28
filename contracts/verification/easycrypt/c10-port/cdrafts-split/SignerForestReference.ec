(* The forest created by successful signing is its returned lower-layer message. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawForest RawLayer RawSigner.
require import PersistentGrind AcceptedContexts ForestOpening ForestRootWitness ForestRootRecording.
require import LayerSignOpening LayerOpeningReplay SignerCoordinates SignerLayerStep SignerComponentHistory.

op signed_forest_reference h s seed digest (signature : raw_signature) =
  exists forest lower,
    forest_root_witness h s seed (hypertree_index digest) forest /\
    forest_opening h seed (hypertree_index digest) digest signature.`2 signature.`3 forest /\
    layer_opening h s seed 0 (hypertree_index digest %/512) (hypertree_index digest %%512)
      forest (nth ([],0,[]) signature.`4 0) lower.

lemma signed_forest_extends h h' s s' seed digest signature :
  extends h h' => extends s s' => signed_forest_reference h s seed digest signature =>
  signed_forest_reference h' s' seed digest signature.
proof.
  move=> hh hs [forest lower [hr [hf hl]]]; exists forest lower.
  smt(forest_root_witness_extends forest_opening_extends layer_opening_extends).
qed.

lemma forest_sign_complete_reference seed0 ht0 digest0 :
  hoare [RawForest(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 ==>
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 res.`3 /\
    forest_opening Independent.rawhistory seed0 ht0 digest0 res.`1 res.`2 res.`3].
proof. conseq (raw_forest_sign_root seed0 ht0 digest0) (raw_forest_sign_opening seed0 ht0 digest0); smt(). qed.

lemma first_layer_rcons h h' s s' seed ht forest layers k signature root :
  extends h h' => extends s s' => 0<=k<2 => size layers=k =>
  (k=0 => layer_opening h' s' seed 0 (ht %/512) (ht %%512) forest signature root) =>
  (k=1 => exists lower, layer_opening h s seed 0 (ht %/512) (ht %%512)
    forest (nth ([],0,[]) layers 0) lower) =>
  exists lower, layer_opening h' s' seed 0 (ht %/512) (ht %%512)
    forest (nth ([],0,[]) (rcons layers signature) 0) lower.
proof.
  move=> hh hs hk hl hnew hold; rewrite nth_rcons hl.
  case (k=0) => hz.
  + exists root; smt().
  have [lower ho] := hold _; first smt().
  exists lower; smt(layer_opening_extends).
qed.

lemma finish_records_forest seed0 digest0 :
  hoare [RawSigner(Independent).finish : seed=seed0 /\ digest=digest0 ==>
    res<>None => signed_forest_reference Independent.rawhistory Independent.secrethistory
      seed0 digest0 (oget res)].
proof.
  proc; seq 2 : (seed=seed0 /\ digest=digest0 /\ ht=hypertree_index digest0 /\
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht forest.`3 /\
    forest_opening Independent.rawhistory seed0 ht digest0 forest.`1 forest.`2 forest.`3).
  + call (forest_sign_complete_reference seed0 (hypertree_index digest0) digest0); auto.
  exists* forest; elim* => forest0.
  wp; while (seed=seed0 /\ digest=digest0 /\ ht=hypertree_index digest0 /\ forest=forest0 /\
    0<=layer<=2 /\ idx_tree=signer_tree ht layer /\
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht forest0.`3 /\
    forest_opening Independent.rawhistory seed0 ht digest0 forest0.`1 forest0.`2 forest0.`3 /\
    (ok => size layers=layer /\ (layer=0 => current=forest0.`3) /\
      (1<=layer => exists lower, layer_opening Independent.rawhistory Independent.secrethistory
        seed0 0 (ht %/512) (ht %%512) forest0.`3 (nth ([],0,[]) layers 0) lower))).
  + exists* layer,current,layers,Independent.rawhistory,Independent.secrethistory;
      elim* => k cur layers0 h0 s0 lower0.
    wp; call (layer_sign_history_opening seed0 k (signer_tree (hypertree_index digest0) (k+1))
      (signer_tree (hypertree_index digest0) k %%512) cur s0 h0).
    auto; move=> &m [he [hinv [hloop hok]]].
    have hk : 0<=k<2 by smt().
    have hcoord := signer_coordinate_step (hypertree_index digest0) k (hypertree_index_range digest0) hk.
    split; first smt(extends_refl).
    move=> _ result h s [hs [hh ho]].
    have hr : forest_root_witness h s seed0 (hypertree_index digest0) forest0.`3
      by apply (forest_root_witness_extends h0 h s0 s); smt().
    have hf : forest_opening h seed0 (hypertree_index digest0) digest0 forest0.`1 forest0.`2 forest0.`3
      by apply (forest_opening_extends h0 h); smt().
    case (result=None) => hn; first smt().
    have hp := first_layer_rcons h0 h s0 s seed0 (hypertree_index digest0)
      forest0.`3 layers0 k (oget result).`1 (oget result).`2 hh hs hk _ _ _.
    - smt().
    - move: ho; rewrite /signer_tree; smt().
    - move=> hlast; exists lower0; smt().
    smt(size_rcons).
  auto; rewrite /signer_tree /signed_forest_reference; smt().
qed.
