require import AllCore List.
require import C10RawOracle C10HashDomains RawKeygen HmsgShapes.
require import IndependentWidths RawSignature C10Bytes ClientGuessCandidates ForsInputSeparation.
require import NodeQueryDomain.

lemma checked seed a rows n :
  size seed=32 => size a=32 => rows_width n rows => n=13 \/ n=43 =>
  node_query (seed ++ a ++ flatten (map pad rows)).
proof.
  exact (node_query_compress seed a rows n).
qed.
