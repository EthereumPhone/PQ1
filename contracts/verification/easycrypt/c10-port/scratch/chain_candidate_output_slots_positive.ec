require import AllCore List Distr DList.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion FullPrefix.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainSessionView ChainByteCandidates RedactedChainOracle ChainVariableSessionCost.
require import RawKeygen LeafCandidateCount ChainCandidateMass.
require import ChainTableInstallation VisibleChainInstallation ChainVisibleGuess.
require import VisibleChainCandidateBudget.

lemma checked (A <: ByteClient {-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare[VisibleChainCandidates(ChainByteCandidates(A)).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    size (chain_variable_nodes res)<=chain_candidate_budget qr qs+86].
proof.
  move=> hr hs; exact (visible_chain_candidate_budget A qr qs hr hs).
qed.
