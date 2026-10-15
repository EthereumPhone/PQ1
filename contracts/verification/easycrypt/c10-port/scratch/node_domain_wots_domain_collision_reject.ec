require import AllCore List FMap RadixEncoding.
require import C10RawOracle RawKeygen RawWots RawSignature ClientGuessCandidates.
require import LinearChain RawChainTrace WotsReference WotsChainSplit WotsLeafReference WotsReferenceRoot.
require import WotsRecoveryTrace RecoveryCompression RawRecoveryTrace WotsSignatureValue.
require import VerifierWotsOpening PublicNodeZero WotsZeroSentinel.
require import NodeQueryDomain DomainNodeCollision DomainLinearCollision HmsgShapes.
require import DomainWotsOpening.

lemma checked h s seed layer tree kp message sigma count root :
  size seed=32 =>
  wots_root h s seed layer tree kp root => rows_width 43 sigma => 0<=count<4294967296 =>
  wots_recovery_trace h seed layer tree kp message sigma count root =>
   !public_node_zero h =>
  wots_verifier_opening h s seed layer tree kp message root (sigma,count).
proof.
  exact (domain_recovery_trace_opens_reference h s seed layer tree kp message sigma count root).
qed.
