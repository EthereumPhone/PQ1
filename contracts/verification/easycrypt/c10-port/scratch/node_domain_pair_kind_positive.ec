require import AllCore List.
require import C10RawOracle C10HashDomains RawKeygen HmsgShapes.
require import IndependentWidths RawSignature C10Bytes ClientGuessCandidates ForsInputSeparation.
require import NodeQueryDomain.

lemma checked seed layer tree kind kp ci cp ha lhs rhs :
  size seed=32 => size lhs=16 => size rhs=16 => be 4 kind <> be 4 0 =>
  node_query (seed ++ address layer tree kind kp ci cp ha ++ pad lhs ++ pad rhs).
proof.
  exact (node_query_pair seed layer tree kind kp ci cp ha lhs rhs).
qed.
