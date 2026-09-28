(* Missing reference messages differ from every retained returned component message. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle C10HashDomains RawKeygen RawForest RawSigner.
require import ExposureLog ExposureSupport ExposureReferences.
require import MerkleRootWitness ForestRootWitness LayerSignOpening VerifierWotsOpening.
require import SubtreeOpeningCases ForestOpeningCases.

op returned_top_message h s seed root (entries : signing_exposure list) tree value =
  exists message signature d top, List.mem entries (message,signature) /\
    h.[hmsg_input seed root (pad signature.`1) message]=Some d /\ hypertree_index d %/512=tree /\
    merkle_root_witness h s seed 0 tree value /\
    layer_opening h s seed 1 0 tree value (nth ([],0,[]) signature.`4 1) top.
op returned_bottom_message h s seed root (entries : signing_exposure list) ht value =
  exists message signature d lower, List.mem entries (message,signature) /\
    h.[hmsg_input seed root (pad signature.`1) message]=Some d /\ hypertree_index d=ht /\
    forest_root_witness h s seed ht value /\
    layer_opening h s seed 0 (ht %/512) (ht %%512) value (nth ([],0,[]) signature.`4 0) lower.

lemma logged_component_messages h s seed root entries message signature d :
  exposures_supported h s seed root entries => List.mem entries (message,signature) =>
  h.[hmsg_input seed root (pad signature.`1) message]=Some d =>
  exists forest lower,
    returned_bottom_message h s seed root entries (hypertree_index d) forest /\
    returned_top_message h s seed root entries (hypertree_index d %/512) lower.
proof.
  move=> hs hm hd.
  have [ha [forest lower upper top [hf [ho [hb [hr ht]]]]]] :=
    logged_digest_references h s seed root entries message signature d hs hm hd.
  exists forest upper; split.
  + exists message signature d lower; smt().
  exists message signature d top; smt().
qed.

op new_top_component h s seed root entries d (sig : raw_signature) =
  exists lower leaf,
    !returned_top_message h s seed root entries (hypertree_index d %/512) lower /\
    wots_verifier_opening h s seed 1 0 (hypertree_index d %/512)
      lower leaf ((nth ([],0,[]) sig.`4 1).`1,(nth ([],0,[]) sig.`4 1).`2).
op new_bottom_component h s seed root entries d (sig : raw_signature) =
  exists forest lower bottom_leaf top_leaf,
    linked_forest_layers h s seed d sig forest lower bottom_leaf top_leaf /\
    !returned_bottom_message h s seed root entries (hypertree_index d) forest.

lemma missing_top_is_new_component h s seed root entries d sig :
  unrecorded_top_message h s seed d sig => new_top_component h s seed root entries d sig.
proof.
  move=> [lower leaf [hn ho]]; exists lower leaf; split; last exact ho.
  rewrite /returned_top_message; smt().
qed.

lemma missing_forest_is_new_component h s seed root entries d sig :
  unrecorded_forest_message h s seed d sig => new_bottom_component h s seed root entries d sig.
proof.
  move=> [forest lower bottom_leaf top_leaf [hl hn]].
  exists forest lower bottom_leaf top_leaf; split; first exact hl.
  rewrite /returned_bottom_message; smt().
qed.
