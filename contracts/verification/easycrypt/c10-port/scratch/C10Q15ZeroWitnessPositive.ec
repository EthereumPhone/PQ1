require import AllCore List Distr FMap StdOrder DList DBool.
require import C10RawOracle C10Counter C10Bytes C10Randomizer C10RawGrind RawKeygen PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion FullSession FullSessionCost FullPrefix ByteSession ByteBound.
require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision PublicCollisionState BytePublicCollision.
require import RawWots PersistentGrind RawCountRecorded WotsReferenceRoot RawWotsRecovery WotsZeroSentinel PublicNodeZero BytePublicNodeBad.
import RealOrder.

op zero_digest = nseq 128 false ++ bytes_to_bits (nseq 16 0).
lemma zero_digest_width : size zero_digest=256.
proof. by rewrite /zero_digest size_cat bytes_to_bits_size !size_nseq. qed.
lemma zero_node_witness : node zero_digest=nseq 16 0.
proof.
  rewrite (node_exact zero_digest zero_digest_width) /compact_r /truncate_r /zero_digest.
  rewrite drop_size_cat 1:size_nseq 1:// bytes_bits_roundtrip; smt(all_nseq).
qed.
lemma zero_is_possible : public_node_zero (empty.[[]<-zero_digest]).
proof.
  rewrite /public_node_zero; exists [] zero_digest; by rewrite get_set_sameE zero_node_witness.
qed.
lemma zero_digest_support : zero_digest \in full_digest.
proof.
  rewrite /full_digest supp_dlist 1:// zero_digest_width /=.
  apply/allP => b hb; exact (supp_dbool b).
qed.
