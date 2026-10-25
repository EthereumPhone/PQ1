(* The actual accepted wrapper byte output lies in the six existing cases.
   This is a qualitative partition; probability charges are separate. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid PrefixIdeal.
require import RawKeygen RawSigner RawSignature KeygenPrefixes KeygenExhaustion.
require import WrapperSession WrapperByteSession WrapperExposureLog WrapperQueryDriver.
require import ExposureLog ClientQueryLog ExposureSupport ExposureWidths ExposureAccounting MinimumExposureSupport.
require import WrapperExposureHistory WrapperExposureWidths WrapperActualForest.
require import ActualExposurePartition NumericalByteCases MemoNodeCollision PublicNodeZero.
require import ByteEncodingCharge ActualWotsCut ActualForsOpening CoveredOutputPool.

lemma wrapper_byte_typed_canonical_history
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs0 :
  0<=qs0 =>
  hoare [IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run : WrapperLimits.sign_cap=qs0 ==>
    exposures_supported Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries /\
    minimum_entries Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries /\
    exposures_width ExposureLog.entries /\
    exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls qs0].
proof.
  move=> hqs; conseq (wrapper_byte_canonical_history A qs0 hqs) (wrapper_byte_exposure_width A); smt().
qed.

lemma wrapper_byte_actual_partition
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) seed0 qs0 :
  0<=qs0 =>
  hoare [IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run : WrapperLimits.sign_cap=qs0 /\
    pad (node KeygenInputs.public_seed)=seed0 ==>
    minimum_entries Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries /\
    (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      actual_exposure_partition Independent.rawhistory Independent.secrethistory
        WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output)].
proof.
  move=> hqs; conseq (wrapper_byte_typed_canonical_history A qs0 hqs) (wrapper_byte_actual_forest A seed0);
    rewrite /exposure_accounting; smt(actual_forest_partition).
qed.

lemma wrapper_byte_numerical_cases
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs :
  0<=qs =>
  hoare[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run : WrapperLimits.sign_cap=qs ==>
    res => numerical_output_cases Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output res].
proof.
  move=> hs; proc*; exists* (pad (node KeygenInputs.public_seed)); elim*=> seed0.
  call (wrapper_byte_actual_partition A seed0 qs hs); auto;
    rewrite /numerical_output_cases; smt(actual_partition_cut_cases actual_partition_covered).
qed.
