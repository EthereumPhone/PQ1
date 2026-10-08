(* The chain backend preserves bounded termination for the original byte client. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion PreparedGrind.
require import RawSigner FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import ChainValueView ChainKeygenView ChainSignerView ChainSessionView ChainByteCandidates.
require import TargetByteLossless.

lemma chain_preparation_lossless (O <: ChainOracle) :
  islossless O.hash => islossless O.value => islossless ChainPreparation(O).run.
proof. move=> hh hv; proc; call (chain_keygen_root_lossless O hh hv); auto. qed.

lemma chain_session_sign_lossless
  (O <: ChainOracle {-FullSession,-ExposureLog,-ClientQueryLog}) :
  islossless O.hash => islossless O.derive => islossless O.value => islossless ChainSession(O).sign.
proof.
  move=> hh hd hv; proc; sp 1; if; auto; wp;
    call (chain_signer_sign_lossless O hh hd hv); auto.
qed.
lemma chain_exposure_sign_lossless
  (O <: ChainOracle {-FullSession,-ExposureLog,-ClientQueryLog}) :
  islossless O.hash => islossless O.derive => islossless O.value => islossless ChainExposureSession(O).sign.
proof.
  move=> hh hd hv; proc; wp; call (chain_session_sign_lossless O hh hd hv); auto.
qed.
lemma chain_query_driver_lossless
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  (forall (V <: FullClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless O.value => islossless ChainQueryDriver(A,O).run.
proof.
  move=> ha hh hd hv; proc; seq 5 : true 1%r 1%r 0%r 0%r => //.
  + call (ha (ChainExposureSession(O)) (query_exposure_hash_lossless (ChainPrefix(O)) hh)
      (chain_exposure_sign_lossless O hh hd hv)); wp; inline FullSession(ChainPrefix(O)).init; auto.
  sp 2; if; auto; call (signer_verify_lossless (ChainPrefix(O)) hh); auto.
qed.
lemma chain_query_context_lossless
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  (forall (V <: FullClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless O.value => islossless ChainQueryContext(A,O).run.
proof.
  move=> ha hh hd hv; proc; call (chain_query_driver_lossless A O ha hh hd hv).
  call (chain_preparation_lossless O hh hv); auto.
qed.
lemma chain_byte_candidates_lossless
  (A <: ByteClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless O.value => islossless ChainByteCandidates(A,O).run.
proof.
  move=> ha hh hd hv; proc; wp.
  call (chain_query_context_lossless (ByteLift(A)) O _ hh hd hv).
  + move=> V hvh hvs; exact (byte_lift_lossless A V ha hvh hvs).
  auto.
qed.
