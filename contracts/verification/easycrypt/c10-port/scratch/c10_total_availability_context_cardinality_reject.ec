require import AllCore List Distr FMap IntDiv BitEncoding StdOrder.
require import C10RawOracle C10Bytes C10Counter RawKeygen RawSignature RawWots.
require import ByteSession RawCountRecorded RawByteValues RawSignerBytes WotsInputSeparation.
require import WotsAcceptanceMass MemoRejectCompletion.
import BS2Int RField RealOrder.
require import WotsRejectDomain.

lemma checked : size wots_context_indices=2^255.
proof. exact wots_context_cardinality. qed.
