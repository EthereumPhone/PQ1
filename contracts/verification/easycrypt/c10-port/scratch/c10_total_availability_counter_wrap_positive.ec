require import AllCore List Distr FMap IntDiv BitEncoding StdOrder.
require import C10RawOracle C10Bytes C10Counter RawKeygen RawSignature RawWots.
require import ByteSession RawCountRecorded RawByteValues RawSignerBytes WotsInputSeparation.
require import WotsAcceptanceMass MemoRejectCompletion.
import BS2Int RField RealOrder.
require import WotsRejectDomain.

lemma checked stem n : 0<=n<=2^256 => uniq (wots_count_schedule stem n).
proof. exact (wots_count_schedule_unique stem n). qed.
