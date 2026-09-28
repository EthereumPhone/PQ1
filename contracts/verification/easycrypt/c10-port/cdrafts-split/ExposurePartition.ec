(* Four explicit uncharged residual cases for the same new-message forgery. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains RawKeygen RawForest RawSigner RawSignature.
require import ExposureLog ExposureSupport ExposureWidths ExposureCoverage ExposureComponents ExposureAccounting.
require import MerkleRootWitness ForestRootWitness ForestOpeningCases SessionForestExtraction MemoNodeCollision.
require import ByteReplay.

op exposure_forgery_cases h s seed root entries d (sig : raw_signature) =
  new_top_component h s seed root entries d sig \/
  new_bottom_component h s seed root entries d sig \/
  (linked_private_openings h s seed d sig /\
    unreturned_private_opening h s seed root entries d sig.`2) \/
  (linked_private_openings h s seed d sig /\
    returned_coverage h seed root entries d /\ returned_private_values h seed root entries d sig.`2).

lemma forest_cases_exposure_partition h s seed root entries d sig :
  exposures_supported h s seed root entries => exposures_width entries => !public_node_collision h =>
  forest_opening_cases h s seed d sig => exposure_forgery_cases h s seed root entries d sig.
proof.
  move=> hs hw hn [ht | [hf | hp]].
  + left; exact (missing_top_is_new_component h s seed root entries d sig ht).
  + right; left; exact (missing_forest_is_new_component h s seed root entries d sig hf).
  have hprivate : forest_private_openings h s seed (hypertree_index d) d sig.`2
    by move: hp; rewrite /linked_private_openings; smt().
  have hc := private_opening_coverage_partition h s seed root entries d sig.`2 hs hw hn hprivate.
  right; right; smt().
qed.

op new_message_exposure_partition h s seed root entries =
  merkle_root_witness h s seed 1 0 root /\
  exists message sig d, size message=32 /\ signature_width sig /\
    !List.mem (exposure_messages entries) message /\ accept_digest d /\
    h.[hmsg_input seed (pad root) (pad sig.`1) message]=Some d /\
    exposure_forgery_cases h s seed (pad root) entries d sig.

lemma new_message_forest_partition h s seed root entries :
  exposures_supported h s seed (pad root) entries => exposures_width entries => !public_node_collision h =>
  new_message_forest_opening h s seed root (exposure_messages entries) =>
  new_message_exposure_partition h s seed root entries.
proof.
  move=> hs hw hn [hr [message sig [hm [hwidth [hf [d [ha [hd hc]]]]]]]].
  split; first exact hr.
  exists message sig d.
  have hp := forest_cases_exposure_partition h s seed (pad root) entries d sig hs hw hn hc.
  smt().
qed.

lemma partition_message_input_new seed root entries message (sig : raw_signature) :
  exposures_width entries => signature_width sig =>
  !List.mem (exposure_messages entries) message =>
  forall oldmessage oldsig, List.mem entries (oldmessage,oldsig) =>
    hmsg_input seed (pad root) (pad sig.`1) message <>
      hmsg_input seed (pad root) (pad oldsig.`1) oldmessage.
proof.
  move=> hw hs hn oldmessage oldsig hm.
  have he : message<>oldmessage by move: hn; rewrite /exposure_messages; smt(mapP).
  have ho : signature_width oldsig by smt().
  have hr : size (pad sig.`1)=size (pad oldsig.`1)
    by move: hs ho; rewrite /signature_width /pad !size_cat; smt().
  smt(hmsg_message_injective).
qed.
