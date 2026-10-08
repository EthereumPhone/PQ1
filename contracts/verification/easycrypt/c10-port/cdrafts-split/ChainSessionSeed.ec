(* The selected public seed is exactly the seed used by the adaptive session. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainSessionView ChainByteCandidates.

lemma chain_driver_seed
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) seed0 :
  hoare[ChainQueryDriver(A,O).run : seed=seed0 ==> FullSession.seed=seed0].
proof.
  proc; sp 0; seq 5 : (FullSession.seed=seed0).
  + call (_ : FullSession.seed=seed0).
    - proc; call (_ : FullSession.seed=seed0 ==> FullSession.seed=seed0).
      * proc; sp 1; if; last by auto.
        wp; call (_ : true ==> true); first by trivial.
        auto.
      if; auto.
    - proc; inline ChainSession(O).sign; wp; sp 4; if; last by auto.
      wp; call (_ : true ==> true); first by trivial.
      auto.
    wp; inline FullSession(ChainPrefix(O)).init; auto.
  sp 2; if; last by auto.
  call (_ : true ==> true); first by trivial.
  auto.
qed.
lemma chain_context_seed
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) seed0 :
  hoare[ChainQueryContext(A,O).run : pad(node KeygenInputs.public_seed)=seed0 ==> FullSession.seed=seed0].
proof.
  proc; call (chain_driver_seed A O seed0).
  call (_ : pad(node KeygenInputs.public_seed)=seed0 ==> res.`3=seed0).
  + proc; call (_ : true ==> true); first by trivial.
    auto.
  auto.
qed.
lemma chain_candidates_seed
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) seed0 :
  hoare[ChainByteCandidates(A,O).run : pad(node KeygenInputs.public_seed)=seed0 ==> FullSession.seed=seed0].
proof. proc; wp; call (chain_context_seed (ByteLift(A)) O seed0); auto. qed.
lemma original_candidates_seed
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) seed0 :
  hoare[OriginalWotsCandidates(A,Independent).run : pad(node KeygenInputs.public_seed)=seed0 ==> FullSession.seed=seed0].
proof.
  conseq (chain_byte_candidates_projection A Independent) (chain_candidates_seed A (ConcreteChain(Independent)) seed0); smt().
qed.
