(* A selected actual-output event implies a hit on an unopened prepared cache entry. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates ChainContextCoupling.
require import ChainReferenceEntries ChainCacheInvariant ChainReferenceSampling ChainCacheConstruction.
require import ObservedValueOpening ObservedUnreturnedCut ActualWotsCoordinate ChainSessionSeed.

lemma complete_chain_self :
  equiv[CompleteChainCache.sample ~ CompleteChainCache.sample :
    ={glob Independent,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent,ChainStage.values}].
proof. by sim. qed.
lemma complete_chain_coupled_cache c :
  equiv[CompleteChainCache.sample ~ CompleteChainCache.sample :
    ={glob Independent,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    (ChainStage.seed{1},ChainStage.layer{1},ChainStage.tree{1},ChainStage.kp{1},ChainStage.index{1})=c ==>
    ={glob Independent,ChainStage.values} /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c ChainStage.values{1}].
proof. conseq complete_chain_self (complete_chain_constructs c) _; smt(). qed.

lemma observed_actual_cut_seed_unopened
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) qs0 seed0 :
  0<=qs0 =>
  hoare[ChainByteCandidates(A,ObservedChain(Independent)).run :
    FullLimits.sign_cap=qs0 /\ ChainStage.seed=seed0 /\ seed0=pad(node KeygenInputs.public_seed) /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ !ChainRevelation.opened ==>
    FullSession.seed=seed0 /\
    (selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries res (ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut) =>
    !ChainRevelation.opened)].
proof.
  move=> hqs; conseq (observed_actual_cut_unopened A qs0 hqs)
    (chain_candidates_seed A (ObservedChain(Independent)) seed0); smt().
qed.
lemma prepared_actual_cut_coupling
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) qs0 c values :
  0<=qs0 =>
  equiv[ChainByteCandidates(A,ObservedChain(Independent)).run ~ ChainByteCandidates(A,CachedChain).run :
    ={glob A,glob FullSession,glob FullLimits,glob KeygenInputs,glob ExposureLog,glob ClientQueryLog,
      Independent.rawhistory,Independent.secrethistory,ChainRevelation.opened,ChainCut.cut,
      ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainStage.values} /\
    FullLimits.sign_cap{1}=qs0 /\ ChainStage.seed{1}=pad(node KeygenInputs.public_seed{1}) /\
    valid_chain_address ChainStage.layer{1} ChainStage.tree{1} ChainStage.kp{1} ChainStage.index{1} /\
    0<=ChainCut.cut{1}<7 /\ !ChainRevelation.opened{1} /\
    (ChainStage.seed{1},ChainStage.layer{1},ChainStage.tree{1},ChainStage.kp{1},ChainStage.index{1})=c /\
    ChainStage.values{1}=values /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c values ==>
    selected_wots_cut Independent.rawhistory{1} Independent.secrethistory{1} FullSession.seed{1} FullSession.root{1}
      ExposureLog.entries{1} res{1} (ChainStage.layer{1},ChainStage.tree{1},ChainStage.kp{1},ChainStage.index{1},ChainCut.cut{1}) =>
    !ChainRevelation.opened{2} /\ mem res{2} (nth (nseq 16 0) ChainStage.values{2} ChainCut.cut{2})].
proof.
  move=> hqs.
  conseq (chain_context_cache_coupling (ChainByteCandidates(A)) c values)
    (observed_actual_cut_seed_unopened A qs0 c.`1 hqs) _.
  + smt().
  rewrite /selected_wots_cut /complete_chain_cache /stored_wots_values /=; smt().
qed.
