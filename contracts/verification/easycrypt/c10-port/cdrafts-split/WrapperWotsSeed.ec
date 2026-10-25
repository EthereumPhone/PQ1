(* The selected chain seed is the actual initialized wrapper seed. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainSessionView WrapperWotsReleaseSession WrapperWotsChainContext.

lemma wrapper_wots_chain_driver_seed
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) seed0 :
  hoare [WrapperWotsReleaseDriver(A,ChainPrefix(O),O).run : seed=seed0 ==> WrapperSession.seed=seed0].
proof.
  proc; seq 5 : (WrapperSession.seed=seed0).
  + call (_ : WrapperSession.seed=seed0).
    - proc; call (_ : WrapperSession.seed=seed0 ==> WrapperSession.seed=seed0).
      * proc; sp 1; if; last by auto.
        wp; call (_ : true ==> true); first by trivial. auto.
      if; auto.
    - proc; wp; call (_ : WrapperSession.seed=seed0 ==> WrapperSession.seed=seed0).
      * proc; sp 1; if; last by auto.
        wp; call (_ : true ==> true); first by trivial. auto.
      auto.
    wp; inline WrapperSession(ChainPrefix(O)).init; auto.
  sp 2; if; last by auto.
  call (_ : true ==> true); first by trivial. auto.
qed.

lemma wrapper_wots_chain_context_seed
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) seed0 :
  hoare [WrapperChainWotsContext(A,O).run : pad(node KeygenInputs.public_seed)=seed0 ==> WrapperSession.seed=seed0].
proof.
  proc; call (wrapper_wots_chain_driver_seed A O seed0).
  call (_ : pad(node KeygenInputs.public_seed)=seed0 ==> res.`3=seed0).
  + proc; call (_ : true ==> true); first by trivial. auto.
  auto.
qed.

lemma wrapper_wots_chain_candidates_seed
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) seed0 :
  hoare [WrapperChainWotsCandidates(A,O).run : pad(node KeygenInputs.public_seed)=seed0 ==> WrapperSession.seed=seed0].
proof. proc; wp; call (wrapper_wots_chain_context_seed (WrapperByteLift(A)) O seed0); auto. qed.

lemma wrapper_wots_original_candidates_seed
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) seed0 :
  hoare [WrapperOriginalWotsCandidates(A,Independent).run : pad(node KeygenInputs.public_seed)=seed0 ==> WrapperSession.seed=seed0].
proof.
  conseq (wrapper_wots_candidates_projection A) (wrapper_wots_chain_candidates_seed A (ConcreteChain(Independent)) seed0); smt().
qed.
