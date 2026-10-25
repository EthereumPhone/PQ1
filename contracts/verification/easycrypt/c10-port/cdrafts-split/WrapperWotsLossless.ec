(* The complete chain wrapper terminates for every admitted adaptive client
   with lossless oracle calls; success and release are not premises. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid RawSigner WrapperSession WrapperByteSession.
require import ExposureLog ClientQueryLog WrapperExposureLog ChainValueView ChainByteLossless.
require import WrapperChainReleasedWots WrapperWotsReleaseSession WrapperWotsChainContext.

lemma wrapper_wots_chain_session_lossless
  (O <: ChainOracle {-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  islossless O.hash => islossless O.derive => islossless O.value =>
  islossless WrapperWotsReleaseSession(ChainPrefix(O),O).sign.
proof.
  move=> hh hd hv; proc; sp 1; if; auto; wp;
    call (wrapper_chain_released_lossless O hh hd hv); auto.
qed.

lemma wrapper_wots_chain_exposure_lossless
  (O <: ChainOracle {-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  islossless O.hash => islossless O.derive => islossless O.value =>
  islossless WrapperWotsReleaseExposure(ChainPrefix(O),O).sign.
proof.
  move=> hh hd hv; proc; wp; call (wrapper_wots_chain_session_lossless O hh hd hv); auto.
qed.

lemma wrapper_wots_chain_driver_lossless
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  (forall (V <: WrapperClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless O.value =>
  islossless WrapperWotsReleaseDriver(A,ChainPrefix(O),O).run.
proof.
  move=> ha hh hd hv; proc; seq 5 : true 1%r 1%r 0%r 0%r => //.
  + call (ha (WrapperWotsReleaseExposure(ChainPrefix(O),O))
      (wrapper_query_hash_lossless (ChainPrefix(O)) hh) (wrapper_wots_chain_exposure_lossless O hh hd hv));
      wp; inline WrapperSession(ChainPrefix(O)).init; auto.
  sp 2; if; auto; call (signer_verify_lossless (ChainPrefix(O)) hh); auto.
qed.

lemma wrapper_wots_chain_context_lossless
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  (forall (V <: WrapperClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless O.value => islossless WrapperChainWotsContext(A,O).run.
proof.
  move=> ha hh hd hv; proc; call (wrapper_wots_chain_driver_lossless A O ha hh hd hv).
  call (chain_preparation_lossless O hh hv); auto.
qed.

lemma wrapper_wots_candidates_lossless
  (A <: WrapperByteClient {-WrapperSession,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless O.value => islossless WrapperChainWotsCandidates(A,O).run.
proof.
  move=> ha hh hd hv; proc; wp.
  call (wrapper_wots_chain_context_lossless (WrapperByteLift(A)) O _ hh hd hv).
  + move=> V hvh hvs; exact (wrapper_byte_lift_lossless A V ha hvh hvs).
  auto.
qed.
