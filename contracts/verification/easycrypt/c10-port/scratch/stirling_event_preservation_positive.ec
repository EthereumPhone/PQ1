require import AllCore List StdOrder.
require import PoolCoverageEvent StirlingPoolWitness StirlingPoolEvent.


lemma checked : forall nodes, pool_coverage nodes=stirling_pool_coverage nodes.
proof.
  exact pool_coverage_stirling.
qed.
