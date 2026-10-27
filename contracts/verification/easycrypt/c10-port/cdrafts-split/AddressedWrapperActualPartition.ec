(* Preserve the existing wrapper non-node cases and refine only the collision
   event to equal-address node collisions in that same experiment. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid PrefixIdeal.
require import RawKeygen RawSigner RawSignature KeygenPrefixes KeygenExhaustion.
require import WrapperSession WrapperByteSession WrapperExposureLog WrapperQueryDriver.
require import ExposureLog ClientQueryLog ExposureSupport ExposureWidths ExposureAccounting MinimumExposureSupport.
require import WrapperExposureHistory WrapperExposureWidths WrapperActualForest.
require import ActualExposurePartition NumericalByteCases MemoNodeCollision PublicNodeZero.
require import ByteEncodingCharge ActualWotsCut ActualForsOpening CoveredOutputPool.

require import WrapperActualPartition AddressedNodeCollision AddressedActualPartition AddressedWrapperActualForest HmsgShapes.

op wrapper_addressed_node_output_cases h s seed root entries output result =
  addressed_node_collision h \/ public_node_zero h \/ wots_encoding_collision h \/
  (result /\ (actual_top_cut h s seed root entries output \/ actual_bottom_cut h s seed root entries output)) \/
  (result /\ actual_output_unreturned h s seed root entries output) \/
  actual_accepted_coverage h seed root entries output.


lemma addressed_wrapper_byte_actual_partition
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) seed0 qs0 :
  size seed0=32 => 0<=qs0 =>
  hoare [IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run : WrapperLimits.sign_cap=qs0 /\
    pad (node KeygenInputs.public_seed)=seed0 ==>
    minimum_entries Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries /\
    (res => addressed_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      actual_exposure_partition Independent.rawhistory Independent.secrethistory
        WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output)].
proof.
  move=> hseed hqs; conseq (wrapper_byte_typed_canonical_history A qs0 hqs) (addressed_wrapper_query_byte_actual_forest A seed0 hseed);
    rewrite /exposure_accounting; smt(addressed_actual_forest_partition).
qed.

lemma wrapper_byte_addressed_node_cases
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs :
  0<=qs =>
  hoare[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run : WrapperLimits.sign_cap=qs ==>
    res => wrapper_addressed_node_output_cases Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output res].
proof.
  move=> hs; proc*; exists* KeygenInputs.public_seed; elim*=> public0.
  have hseed : size (pad (node public0))=32 by smt(pad_node_width node_width).
  call (addressed_wrapper_byte_actual_partition A (pad (node public0)) qs hseed hs); auto;
    rewrite /wrapper_addressed_node_output_cases; smt(actual_partition_cut_cases actual_partition_covered).
qed.
