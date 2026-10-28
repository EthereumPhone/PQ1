(* Equal-address refinement; the original Domain proof family is retained. *)
(* The actual byte-game partition needs only node-domain and accepted-encoding collisions. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion RawKeygen.
require import FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import AddressedActualForest SelectedActualWotsCut SelectedWotsCollision.
require import MemoNodeCollision PublicNodeZero ByteEncodingCharge ActualExposurePartition ActualWotsCut ActualForsOpening CoveredOutputPool.

require import NodeQueryDomain AddressedNodeCollision AddressedActualPartition HmsgShapes.

op selected_encoding_output_cases h s seed root entries output result =
  addressed_node_collision h \/ public_node_zero h \/ selected_accepted_collision h \/
  (result /\ (actual_top_cut h s seed root entries output \/ actual_bottom_cut h s seed root entries output)) \/
  (result /\ actual_output_unreturned h s seed root entries output) \/
  actual_accepted_coverage h seed root entries output.

lemma query_byte_selected_encoding_cases
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs :
  0<=qs =>
  hoare[IndependentGame(ClientQueryContext(ByteLift(A))).run : FullLimits.sign_cap=qs ==>
    res => selected_encoding_output_cases Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res].
proof.
  move=> hs; proc*; exists* KeygenInputs.public_seed; elim*=> public0.
  have hseed : size (pad (node public0))=32 by smt(pad_node_width node_width).
  call (_ : FullLimits.sign_cap=qs /\ pad (node KeygenInputs.public_seed)=pad (node public0) ==>
    size FullSession.seed=32 /\
    (res => addressed_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      actual_exposure_partition Independent.rawhistory Independent.secrethistory
        FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output)).
  + conseq (addressed_query_byte_actual_partition A (pad (node public0)) qs hseed hs)
      (addressed_query_byte_actual_forest A (pad (node public0)) hseed); smt().
  auto;
    rewrite /selected_encoding_output_cases; smt(selected_actual_partition_cut_cases actual_partition_covered).
qed.
