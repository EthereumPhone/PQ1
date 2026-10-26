(* Equal-address refinement; the original Domain proof family is retained. *)
(* Actual verification descends to FORS secrets when both retained references exist. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen RawLayer RawSigner RawSignature RawForest.
require import C10RawGrind C10HashDomains SignerCoordinates MerkleRootWitness VerifierWotsOpening.
require import LayerRecordExtraction VerifierForestRecords SubtreeOpeningCases.
require import ForestOpening ForestRootWitness ForestRecordExtraction MemoNodeCollision PublicNodeZero.

require import ForestOpeningCases AddressedNodeCollision AddressedLayerExtraction AddressedForestExtraction.

lemma addressed_recorded_verifier_forest_cases h s seed d (sig : raw_signature) root :
  size seed=32 => signature_width sig => merkle_root_witness h s seed 1 0 root =>
  verifier_forest_records h seed d sig root =>
  !addressed_node_collision h => !public_node_zero h =>
  forest_opening_cases h s seed d sig.
proof.
  move=> hseed hw hr [forest lower [hf [hb ht]]] hn hz.
  have hw0 : layer_width (nth ([],0,[]) sig.`4 0)
    by move: hw; rewrite /signature_width; smt(allP mem_nth).
  have hw1 : layer_width (nth ([],0,[]) sig.`4 1)
    by move: hw; rewrite /signature_width; smt(allP mem_nth).
  have hi0 : 0<=hypertree_index d %%512<512 by smt(modz_ge0 ltz_mod).
  have hi1 : 0<=hypertree_index d %/512<512
    by smt(hypertree_index_range divz_ge0 ltz_divLR).
  have [top_leaf htop] := addressed_recorded_layer_extracts h s seed 1 0 (hypertree_index d %/512)
    lower (nth ([],0,[]) sig.`4 1) root hseed hw1 hi1 hr ht hn hz.
  case (merkle_root_witness h s seed 0 (hypertree_index d %/512) lower) => hlower.
  + have [bottom_leaf hbottom] := addressed_recorded_layer_extracts h s seed 0 (hypertree_index d %/512)
      (hypertree_index d %%512) forest (nth ([],0,[]) sig.`4 0) lower hseed hw0 hi0 hlower hb hn hz.
    have hlinks : linked_forest_layers h s seed d sig forest lower bottom_leaf top_leaf by smt().
    case (forest_root_witness h s seed (hypertree_index d) forest) => hforest.
    - have hprivate := addressed_recorded_forest_extracts h s seed (hypertree_index d) d sig.`2 sig.`3 forest
        hseed _ _ _ hforest hf hn; first 3 by move: hw; rewrite /signature_width; smt().
      right; right; exists forest lower bottom_leaf top_leaf; smt().
    right; left; exists forest lower bottom_leaf top_leaf; smt().
  left; exists lower top_leaf; smt().
qed.

lemma addressed_verified_records_to_forest h s seed root message (sig : raw_signature) :
  size seed=32 => signature_width sig => merkle_root_witness h s seed 1 0 root =>
  verified_forest_records h seed root message sig =>
  !addressed_node_collision h => !public_node_zero h =>
  verified_forest_opening h s seed root message sig.
proof.
  move=> hseed hw hr [d [ha [he hl]]] hn hz.
  exists d; smt(addressed_recorded_verifier_forest_cases).
qed.
