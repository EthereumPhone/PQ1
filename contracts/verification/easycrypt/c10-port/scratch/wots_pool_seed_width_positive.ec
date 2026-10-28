require import AllCore List FMap IntDiv RadixEncoding.
require import C10RawOracle C10HashDomains RawKeygen RawWots RawForest RawSigner RawSignature.
require import WotsReference WotsReferenceRoot WotsChainSplit VerifierWotsOpening.
require import WotsUnreturnedCut ByteEncodingCharge ExposureComponents ForestOpeningCases.
require import ExposurePartition ExposureCoverage ActualExposurePartition ActualForsOpening.
require import ActualWotsCut SelectedWotsCut SelectedWotsCollision.
require import SelectedActualWotsCut.
lemma checked h s seed root entries output :
  size seed=32 => actual_exposure_partition h s seed root entries output =>
  selected_accepted_collision h \/ actual_top_cut h s seed root entries output \/
    actual_bottom_cut h s seed root entries output \/ actual_output_unreturned h s seed root entries output \/
    actual_covered_output h seed root entries output.
proof. exact (selected_actual_partition_cut_cases h s seed root entries output). qed.
