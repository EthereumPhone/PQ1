(* The actual byte-game partition needs only node-domain and accepted-encoding collisions. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion RawKeygen.
require import FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import AcceptedActualWotsCut AcceptedWotsCollision.
require import MemoNodeCollision PublicNodeZero ByteEncodingCharge ActualExposurePartition ActualWotsCut ActualForsOpening CoveredOutputPool.

require import NodeQueryDomain DomainNodeCollision DomainActualPartition HmsgShapes.

op domain_node_output_cases h s seed root entries output result =
  domain_node_collision h \/ public_node_zero h \/ accepted_wots_encoding_collision h \/
  (result /\ (actual_top_cut h s seed root entries output \/ actual_bottom_cut h s seed root entries output)) \/
  (result /\ actual_output_unreturned h s seed root entries output) \/
  actual_accepted_coverage h seed root entries output.

lemma query_byte_domain_node_cases
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs :
  0<=qs =>
  hoare[IndependentGame(ClientQueryContext(ByteLift(A))).run : FullLimits.sign_cap=qs ==>
    res => domain_node_output_cases Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res].
proof.
  move=> hs; proc*; exists* KeygenInputs.public_seed; elim*=> public0.
  have hseed : size (pad (node public0))=32 by smt(pad_node_width node_width).
  call (domain_query_byte_actual_partition A (pad (node public0)) qs hseed hs); auto;
    rewrite /domain_node_output_cases; smt(accepted_actual_partition_cut_cases actual_partition_covered).
qed.
