require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeQueryDomain DomainNodeCollision.
require import DomainNodeTable.

lemma checked h nodes x d :
  domain_table_recorded h nodes =>  domain_table_recorded h.[x<-d] nodes.
proof.
  exact (domain_table_insert_other h nodes x d).
qed.
