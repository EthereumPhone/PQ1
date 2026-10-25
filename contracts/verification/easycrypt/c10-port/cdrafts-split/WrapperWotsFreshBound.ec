(* A numerical unopened-chain bound with the wrapper's actual candidate
   budget and generic termination obligations fully discharged. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates WrapperWotsChainContext WrapperWotsLossless.
require import ChainVectorInstall DualDigestSampling RedactedChainOracle ChainPublicHybrid.
require import ChainTableInstallation VisibleChainInstallation ChainVisibleGuess.
require import LeafCandidateCount ChainCandidateMass ChainCandidateBound.
require import PrivateValueSampling PublicTargetSampling FreshChainGuess ProgrammedChainBound.
require import WrapperWotsCandidateBudget.
import RealOrder.

lemma wrapper_wots_visible_execution_budget
  (A <: WrapperByteClient {-WrapperSession,-Independent,-ExposureLog,-ClientQueryLog,-WrapperLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare [WrapperChainWotsCandidates(A,RedactedCachedChain).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\ Independent.queries=[] ==>
    leaf_variable_count Independent.queries<=wrapper_wots_candidate_budget qr qs /\ size res<=86].
proof.
  move=> hr hs; proc; wp.
  call (wrapper_wots_context_candidate_cost (WrapperByteLift(A)) qr qs hr hs).
  auto; rewrite /leaf_variable_count; smt(wots_output_candidates_size).
qed.

lemma wrapper_wots_visible_candidate_budget
  (A <: WrapperByteClient {-WrapperSession,-Independent,-ExposureLog,-ClientQueryLog,-WrapperLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare [VisibleChainCandidates(WrapperChainWotsCandidates(A)).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==>
    size (chain_variable_nodes res)<=wrapper_wots_candidate_budget qr qs+86].
proof.
  move=> hr hs; proc; wp.
  call (wrapper_wots_visible_execution_budget A qr qs hr hs).
  wp; inline VisibleChainInstall.run VisibleChainStep.run Independent.init.
  auto; smt(chain_variable_nodes_query_outputs).
qed.

lemma wrapper_wots_programmed_candidate_bound
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,-ChainVectorInstall,-CachedChain,
    -RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=ChainCut.cut{m}<7 => 0<=WrapperLimits.raw_cap{m} => 0<=WrapperLimits.sign_cap{m} =>
  Pr[ProgrammedUnopenedChainGuess(WrapperChainWotsCandidates(A)).run() @ &m : res] <=
    8%r*(wrapper_wots_candidate_budget WrapperLimits.raw_cap{m} WrapperLimits.sign_cap{m}+86+2)%r*(1%r/2%r)^128.
proof.
  move=> ha hc hr hs.
  apply (programmed_unopened_chain_candidate_bound (WrapperChainWotsCandidates(A))
    (wrapper_wots_candidate_budget WrapperLimits.raw_cap{m} WrapperLimits.sign_cap{m}+86) &m).
  + move=> O hh hd hv; exact (wrapper_wots_candidates_lossless A O ha hh hd hv).
  + exact hc.
  + rewrite /wrapper_wots_candidate_budget ; smt().
  conseq (wrapper_wots_visible_candidate_budget A WrapperLimits.raw_cap{m} WrapperLimits.sign_cap{m} hr hs); smt().
qed.

lemma wrapper_wots_fresh_candidate_bound
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,-ChainVectorInstall,-CachedChain,
    -RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample}) &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=ChainCut.cut{m}<7 => 0<=WrapperLimits.raw_cap{m} => 0<=WrapperLimits.sign_cap{m} =>
  Pr[FreshCachedChainGuess(WrapperChainWotsCandidates(A)).run() @ &m : res] <=
    8%r*(wrapper_wots_candidate_budget WrapperLimits.raw_cap{m} WrapperLimits.sign_cap{m}+86+2)%r*(1%r/2%r)^128.
proof.
  move=> ha hc hr hs.
  have hll : forall (O <: ChainOracle {-WrapperChainWotsCandidates(A)}),
    islossless O.hash => islossless O.derive => islossless O.value => islossless WrapperChainWotsCandidates(A,O).run.
  + move=> O hh hd hv; exact (wrapper_wots_candidates_lossless A O ha hh hd hv).
  have he1 : Pr[FreshCachedChainGuess(WrapperChainWotsCandidates(A)).run() @ &m : res]=
    Pr[FreshRedactedChainGuess(WrapperChainWotsCandidates(A)).run() @ &m : res]
    by byequiv (fresh_chain_redaction (WrapperChainWotsCandidates(A)) hll) => //.
  have he2 : Pr[FreshRedactedChainGuess(WrapperChainWotsCandidates(A)).run() @ &m : res]=
    Pr[ProgrammedUnopenedChainGuess(WrapperChainWotsCandidates(A)).run() @ &m : res].
  + byequiv (fresh_redacted_programmed (WrapperChainWotsCandidates(A))) => //; smt().
  rewrite he1 he2; exact (wrapper_wots_programmed_candidate_bound A &m ha hc hr hs).
qed.
