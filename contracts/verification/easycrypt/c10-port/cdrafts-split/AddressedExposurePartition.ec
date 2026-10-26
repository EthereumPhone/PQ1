(* Equal-address refinement; the original Domain proof family is retained. *)
(* Four explicit uncharged residual cases for the same new-message forgery. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains RawKeygen RawForest RawSigner RawSignature.
require import ExposureLog ExposureSupport ExposureWidths ExposureCoverage ExposureComponents ExposureAccounting.
require import MerkleRootWitness ForestRootWitness ForestOpeningCases SessionForestExtraction MemoNodeCollision.
require import ByteReplay.

require import ExposurePartition AddressedNodeCollision AddressedExposureCoverage.

lemma addressed_forest_cases_exposure_partition h s seed root entries d sig :
  size seed=32 => exposures_supported h s seed root entries => exposures_width entries => !addressed_node_collision h =>
  forest_opening_cases h s seed d sig => exposure_forgery_cases h s seed root entries d sig.
proof.
  move=> hseed hs hw hn [ht | [hf | hp]].
  + left; exact (missing_top_is_new_component h s seed root entries d sig ht).
  + right; left; exact (missing_forest_is_new_component h s seed root entries d sig hf).
  have hprivate : forest_private_openings h s seed (hypertree_index d) d sig.`2
    by move: hp; rewrite /linked_private_openings; smt().
  have hc := addressed_private_opening_coverage_partition h s seed root entries d sig.`2 hseed hs hw hn hprivate.
  right; right; smt().
qed.
