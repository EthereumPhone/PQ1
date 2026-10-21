require import AllCore List Distr FMap IntDiv BitEncoding StdOrder.
require import C10RawOracle C10Bytes C10Counter RawKeygen RawSignature RawWots.
require import ByteSession RawCountRecorded RawByteValues RawSignerBytes WotsInputSeparation.
require import WotsAcceptanceMass MemoRejectCompletion.
import BS2Int RField RealOrder.
require import WotsRejectDomain.

lemma checked seed layer tree kp message :
  true => byte_values message => exists c,
    List.mem wots_context_indices c /\
    wots_context_stem seed (be 32 c) = seed ++ address layer tree 0 kp 0 0 0 ++ pad message.
proof. exact (wots_context_covered seed layer tree kp message). qed.
