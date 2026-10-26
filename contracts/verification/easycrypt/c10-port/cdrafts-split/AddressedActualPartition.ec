(* Equal-address refinement; the original Domain proof family is retained. *)
(* The four residual cases refer to the actual verified output, with a shared digest. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid PrefixIdeal.
require import RawKeygen RawSigner RawSignature FullSession ByteSession KeygenPrefixes KeygenExhaustion.
require import ExposureLog ExposureDriver ClientQueryLog ClientQueryDriver ExposureSupport ExposureWidths.
require import ExposureAccounting ExposurePartition ForestOpeningCases ActualForestGame QueryMinimumHistory.
require import MinimumExposureSupport MemoNodeCollision PublicNodeZero.

require import ActualExposurePartition AddressedNodeCollision AddressedActualForest AddressedExposurePartition.

lemma addressed_actual_forest_partition h s seed root entries messages output :
  size seed=32 => exposures_supported h s seed (pad root) entries => exposures_width entries =>
  exposure_messages entries=messages => !addressed_node_collision h =>
  actual_forest_output h s seed root messages output =>
  actual_exposure_partition h s seed (pad root) entries output.
proof.
  move=> hseed hs hw hm hn [hmess [hsig [hnew [d [ha [hd hc]]]]]].
  have hp := addressed_forest_cases_exposure_partition h s seed (pad root) entries d output.`2 hseed hs hw hn hc.
  rewrite /actual_exposure_partition; split; first exact hmess.
  split; first exact hsig.
  split; first smt().
  exists d; smt().
qed.

lemma addressed_query_byte_actual_partition
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) seed0 qs0 :
  size seed0=32 => 0<=qs0 =>
  hoare [IndependentGame(ClientQueryContext(ByteLift(A))).run : FullLimits.sign_cap=qs0 /\
    pad (node KeygenInputs.public_seed)=seed0 ==>
    minimum_entries Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries /\
    (res => addressed_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      actual_exposure_partition Independent.rawhistory Independent.secrethistory
        FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output)].
proof.
  move=> hseed hqs; conseq (query_byte_typed_canonical_history A qs0 hqs) (addressed_query_byte_actual_forest A seed0 hseed);
    rewrite /exposure_accounting; smt(addressed_actual_forest_partition).
qed.
