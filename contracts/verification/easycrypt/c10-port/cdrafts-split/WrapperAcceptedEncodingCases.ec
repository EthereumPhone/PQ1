(* Refine only the encoding case of the addressed-node wrapper partition.
   This is the same initialized game and externally released exposure log. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion RawKeygen HmsgShapes.
require import WrapperSession WrapperByteSession WrapperQueryDriver ExposureLog ClientQueryLog.
require import AcceptedActualWotsCut AcceptedWotsCollision AddressedNodeCollision AddressedWrapperActualPartition.
require import PublicNodeZero ActualExposurePartition ActualWotsCut ActualForsOpening CoveredOutputPool.

op wrapper_accepted_encoding_output_cases h s seed root entries output result =
  addressed_node_collision h \/ public_node_zero h \/ accepted_wots_encoding_collision h \/
  (result /\ (actual_top_cut h s seed root entries output \/ actual_bottom_cut h s seed root entries output)) \/
  (result /\ actual_output_unreturned h s seed root entries output) \/
  actual_accepted_coverage h seed root entries output.

lemma wrapper_byte_accepted_encoding_cases
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs :
  0<=qs =>
  hoare[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run : WrapperLimits.sign_cap=qs ==>
    res => wrapper_accepted_encoding_output_cases Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output res].
proof.
  move=> hs; proc*; exists* KeygenInputs.public_seed; elim*=> public0.
  have hseed : size (pad (node public0))=32 by smt(pad_node_width node_width).
  call (addressed_wrapper_byte_actual_partition A (pad (node public0)) qs hseed hs); auto;
    rewrite /wrapper_accepted_encoding_output_cases; smt(accepted_actual_partition_cut_cases actual_partition_covered).
qed.
