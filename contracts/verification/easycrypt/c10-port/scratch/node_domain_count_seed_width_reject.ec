require import AllCore List.
require import C10RawOracle C10HashDomains RawKeygen HmsgShapes.
require import IndependentWidths RawSignature C10Bytes ClientGuessCandidates ForsInputSeparation.
require import NodeQueryDomain.

lemma checked seed layer tree kp message count :
   size message=16 =>
  !node_query (seed ++ address layer tree 0 kp 0 0 0 ++ pad message ++ be 32 count).
proof.
  exact (node_query_no_count seed layer tree kp message count).
qed.
