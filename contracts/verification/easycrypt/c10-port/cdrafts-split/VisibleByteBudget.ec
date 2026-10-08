(* The independent-vector game uses the original byte query budget plus 86 output nodes. *)
require import AllCore List Distr DList.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion FullPrefix.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainSessionView ChainByteCandidates RedactedChainOracle RedactedSessionCost.
require import ChainTableInstallation VisibleChainInstallation ChainVisibleGuess.

lemma redacted_byte_candidates_cost
  (A <: ByteClient {-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare[ChainByteCandidates(A,RedactedCachedChain).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\ size Independent.queries=0 ==>
    size Independent.queries<=full_public_budget qr qs /\ size res<=86].
proof.
  move=> hr hs; proc; wp; call (redacted_context_cost (ByteLift(A)) qr qs hr hs).
  auto; rewrite /full_public_budget; smt(wots_output_candidates_size).
qed.
lemma visible_byte_candidate_budget
  (A <: ByteClient {-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare[VisibleChainCandidates(ChainByteCandidates(A)).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    size res<=full_public_budget qr qs+86].
proof.
  move=> hr hs; proc; wp.
  call (redacted_byte_candidates_cost A qr qs hr hs).
  wp; inline VisibleChainInstall.run VisibleChainStep.run Independent.init.
  auto; smt(size_cat size_map).
qed.
