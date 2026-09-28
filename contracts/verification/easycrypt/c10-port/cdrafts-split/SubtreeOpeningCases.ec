(* A recorded lower root lets actual recovery descend to the lower WOTS key.
   Absence of that root is retained as an explicit, uncharged top-message event. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen RawLayer RawSigner RawSignature RawForest.
require import C10RawGrind C10HashDomains SignerCoordinates MerkleRootWitness VerifierWotsOpening.
require import LayerRecordExtraction VerifierLayerRecords MemoNodeCollision PublicNodeZero.

op unrecorded_top_message h s seed d (sig : raw_signature) =
  exists lower leaf,
    !merkle_root_witness h s seed 0 (hypertree_index d %/512) lower /\
    wots_verifier_opening h s seed 1 0 (hypertree_index d %/512)
      lower leaf ((nth ([],0,[]) sig.`4 1).`1,(nth ([],0,[]) sig.`4 1).`2).

op paired_layer_openings h s seed d (sig : raw_signature) =
  exists forest lower bottom_leaf top_leaf,
    merkle_root_witness h s seed 0 (hypertree_index d %/512) lower /\
    wots_verifier_opening h s seed 0 (hypertree_index d %/512) (hypertree_index d %%512)
      forest bottom_leaf ((nth ([],0,[]) sig.`4 0).`1,(nth ([],0,[]) sig.`4 0).`2) /\
    wots_verifier_opening h s seed 1 0 (hypertree_index d %/512)
      lower top_leaf ((nth ([],0,[]) sig.`4 1).`1,(nth ([],0,[]) sig.`4 1).`2).

op subtree_opening_cases h s seed d sig =
  unrecorded_top_message h s seed d sig \/ paired_layer_openings h s seed d sig.

op verified_subtree_opening h s seed root message (sig : raw_signature) =
  exists d, accept_digest d /\ h.[hmsg_input seed (pad root) (pad sig.`1) message]=Some d /\
    subtree_opening_cases h s seed d sig.

lemma recorded_verifier_subtree_cases h s seed d (sig : raw_signature) root :
  signature_width sig => merkle_root_witness h s seed 1 0 root =>
  verifier_layer_records h seed d sig root =>
  !public_node_collision h => !public_node_zero h =>
  subtree_opening_cases h s seed d sig.
proof.
  move=> hw hr [forest lower [hb ht]] hn hz.
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
    right; exists forest lower bottom_leaf top_leaf; smt().
  left; exists lower top_leaf; smt().
qed.

lemma verified_records_to_subtree h s seed root message (sig : raw_signature) :
  signature_width sig => merkle_root_witness h s seed 1 0 root =>
  verified_layer_records h seed root message sig =>
  !public_node_collision h => !public_node_zero h =>
  verified_subtree_opening h s seed root message sig.
proof.
  move=> hw hr [d [ha [he hl]]] hn hz.
  exists d; smt(recorded_verifier_subtree_cases).
qed.
