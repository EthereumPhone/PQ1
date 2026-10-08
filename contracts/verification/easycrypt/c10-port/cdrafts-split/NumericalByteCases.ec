(* Every accepted byte output lies in one of the six numerically charged cases. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion RawKeygen.
require import FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import MemoNodeCollision PublicNodeZero ByteEncodingCharge ActualExposurePartition ActualWotsCut ActualForsOpening CoveredOutputPool.

op numerical_output_cases h s seed root entries output result =
  public_node_collision h \/ public_node_zero h \/ wots_encoding_collision h \/
  (result /\ (actual_top_cut h s seed root entries output \/ actual_bottom_cut h s seed root entries output)) \/
  (result /\ actual_output_unreturned h s seed root entries output) \/
  actual_accepted_coverage h seed root entries output.

lemma query_byte_numerical_cases
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs :
  0<=qs =>
  hoare[IndependentGame(ClientQueryContext(ByteLift(A))).run : FullLimits.sign_cap=qs ==>
    res => numerical_output_cases Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res].
proof.
  move=> hs; proc*; exists* (pad (node KeygenInputs.public_seed)); elim*=> seed0.
  call (query_byte_actual_partition A seed0 qs hs); auto;
    rewrite /numerical_output_cases; smt(actual_partition_cut_cases actual_partition_covered).
qed.
