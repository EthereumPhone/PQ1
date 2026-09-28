(* Actual verification descends to FORS secrets when both retained references exist. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen RawLayer RawSigner RawSignature RawForest.
require import C10RawGrind C10HashDomains SignerCoordinates MerkleRootWitness VerifierWotsOpening.
require import LayerRecordExtraction VerifierForestRecords SubtreeOpeningCases.
require import ForestOpening ForestRootWitness ForestRecordExtraction MemoNodeCollision PublicNodeZero.

op linked_forest_layers h s seed d (sig : raw_signature) forest lower bottom_leaf top_leaf =
  merkle_root_witness h s seed 0 (hypertree_index d %/512) lower /\
  forest_opening h seed (hypertree_index d) d sig.`2 sig.`3 forest /\
  wots_verifier_opening h s seed 0 (hypertree_index d %/512) (hypertree_index d %%512)
    forest bottom_leaf ((nth ([],0,[]) sig.`4 0).`1,(nth ([],0,[]) sig.`4 0).`2) /\
  wots_verifier_opening h s seed 1 0 (hypertree_index d %/512)
    lower top_leaf ((nth ([],0,[]) sig.`4 1).`1,(nth ([],0,[]) sig.`4 1).`2).

op unrecorded_forest_message h s seed d sig =
  exists forest lower bottom_leaf top_leaf,
    linked_forest_layers h s seed d sig forest lower bottom_leaf top_leaf /\
    !forest_root_witness h s seed (hypertree_index d) forest.

op linked_private_openings h s seed d (sig : raw_signature) =
  exists forest lower bottom_leaf top_leaf,
    linked_forest_layers h s seed d sig forest lower bottom_leaf top_leaf /\
    forest_root_witness h s seed (hypertree_index d) forest /\
    forest_private_openings h s seed (hypertree_index d) d sig.`2.

op forest_opening_cases h s seed d sig =
  unrecorded_top_message h s seed d sig \/
  unrecorded_forest_message h s seed d sig \/ linked_private_openings h s seed d sig.

op verified_forest_opening h s seed root message (sig : raw_signature) =
  exists d, accept_digest d /\ h.[hmsg_input seed (pad root) (pad sig.`1) message]=Some d /\
    forest_opening_cases h s seed d sig.

lemma recorded_verifier_forest_cases h s seed d (sig : raw_signature) root :
  signature_width sig => merkle_root_witness h s seed 1 0 root =>
  verifier_forest_records h seed d sig root =>
  !public_node_collision h => !public_node_zero h =>
  forest_opening_cases h s seed d sig.
proof.
  move=> hw hr [forest lower [hf [hb ht]]] hn hz.
  have hw0 : layer_width (nth ([],0,[]) sig.`4 0)
    by move: hw; rewrite /signature_width; smt(allP mem_nth).
  have hw1 : layer_width (nth ([],0,[]) sig.`4 1)
    by move: hw; rewrite /signature_width; smt(allP mem_nth).
  have hi0 : 0<=hypertree_index d %%512<512 by smt(modz_ge0 ltz_mod).
  have hi1 : 0<=hypertree_index d %/512<512
    by smt(hypertree_index_range divz_ge0 ltz_divLR).
  have [top_leaf htop] := recorded_layer_extracts h s seed 1 0 (hypertree_index d %/512)
    lower (nth ([],0,[]) sig.`4 1) root hw1 hi1 hr ht hn hz.
  case (merkle_root_witness h s seed 0 (hypertree_index d %/512) lower) => hlower.
  + have [bottom_leaf hbottom] := recorded_layer_extracts h s seed 0 (hypertree_index d %/512)
      (hypertree_index d %%512) forest (nth ([],0,[]) sig.`4 0) lower hw0 hi0 hlower hb hn hz.
    have hlinks : linked_forest_layers h s seed d sig forest lower bottom_leaf top_leaf by smt().
    case (forest_root_witness h s seed (hypertree_index d) forest) => hforest.
    - have hprivate := recorded_forest_extracts h s seed (hypertree_index d) d sig.`2 sig.`3 forest
        _ _ _ hforest hf hn; first 3 by move: hw; rewrite /signature_width; smt().
      right; right; exists forest lower bottom_leaf top_leaf; smt().
    right; left; exists forest lower bottom_leaf top_leaf; smt().
  left; exists lower top_leaf; smt().
qed.

lemma verified_records_to_forest h s seed root message (sig : raw_signature) :
  signature_width sig => merkle_root_witness h s seed 1 0 root =>
  verified_forest_records h seed root message sig =>
  !public_node_collision h => !public_node_zero h =>
  verified_forest_opening h s seed root message sig.
proof.
  move=> hw hr [d [ha [he hl]]] hn hz.
  exists d; smt(recorded_verifier_forest_cases).
qed.
