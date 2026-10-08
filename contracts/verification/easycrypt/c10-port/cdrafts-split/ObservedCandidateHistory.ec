(* The passive chain observer retains the original complete return-history evidence. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen FullSession ByteSession.
require import ExposureLog ExposureDriver ClientQueryLog ClientQueryDriver ExposureSupport ExposureGameHistory.
require import ChainValueView ChainStageSampling CachedChainOracle ChainSessionView ChainByteCandidates ChainContextCoupling.

lemma observed_wots_candidates_projection
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) :
  equiv[OriginalWotsCandidates(A,Independent).run ~ ChainByteCandidates(A,ObservedChain(Independent)).run :
    ={glob A,glob Independent,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog} ==>
    ={res,glob A,glob Independent,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof.
  transitivity ChainByteCandidates(A,ConcreteChain(Independent)).run
    (={glob A,glob Independent,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog} ==>
      ={res,glob A,glob Independent,glob FullSession,glob ExposureLog,glob ClientQueryLog})
    (={glob A,glob Independent,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog} ==>
      ={res,glob A,glob Independent,glob FullSession,glob ExposureLog,glob ClientQueryLog}) => //.
  + smt().
  + conseq (chain_byte_candidates_projection A Independent); smt().
  conseq (chain_context_observer_projection (ChainByteCandidates(A))); smt().
qed.
lemma query_context_supported
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs0 :
  0<=qs0 =>
  hoare[ClientQueryContext(A,Independent).run : FullLimits.sign_cap=qs0 ==>
    exposures_supported Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries].
proof.
  move=> hqs.
  have he : equiv[ClientQueryContext(A,Independent).run ~ ExposureContext(A,Independent).run :
    ={glob A,glob Independent,glob FullLimits,glob KeygenInputs} ==>
    ={glob Independent,glob FullSession,glob ExposureLog}]
    by symmetry; conseq (client_query_context_projection A Independent); smt().
  conseq he (exposure_context_history A qs0 hqs).
  + move=> &m hm; exists (glob A){m} FullLimits.raw_cap{m} FullLimits.sign_cap{m}
      KeygenInputs.message{m} KeygenInputs.public_seed{m} KeygenInputs.random{m}
      Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}; smt().
  smt().
qed.
lemma original_wots_candidates_supported
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs0 :
  0<=qs0 =>
  hoare[OriginalWotsCandidates(A,Independent).run : FullLimits.sign_cap=qs0 ==>
    exposures_supported Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries].
proof. move=> hqs; proc; wp; call (query_context_supported (ByteLift(A)) qs0 hqs); auto. qed.
lemma observed_wots_candidates_supported
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) qs0 :
  0<=qs0 =>
  hoare[ChainByteCandidates(A,ObservedChain(Independent)).run : FullLimits.sign_cap=qs0 ==>
    exposures_supported Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries].
proof.
  move=> hqs.
  have he : equiv[ChainByteCandidates(A,ObservedChain(Independent)).run ~ OriginalWotsCandidates(A,Independent).run :
    ={glob A,glob Independent,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog} ==>
    ={glob Independent,glob FullSession,glob ExposureLog}]
    by symmetry; conseq (observed_wots_candidates_projection A); smt().
  conseq he (original_wots_candidates_supported A qs0 hqs).
  + smt().
  smt().
qed.
