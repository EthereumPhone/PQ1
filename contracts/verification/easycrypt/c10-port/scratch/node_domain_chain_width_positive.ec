require import AllCore List.
require import C10RawOracle C10HashDomains RawKeygen HmsgShapes.
require import IndependentWidths RawSignature C10Bytes ClientGuessCandidates ForsInputSeparation.
require import NodeQueryDomain.

lemma checked seed a value :
  size seed=32 => size a=32 => size value=16 => node_query (seed ++ a ++ pad value).
proof.
  exact (node_query_chain seed a value).
qed.
