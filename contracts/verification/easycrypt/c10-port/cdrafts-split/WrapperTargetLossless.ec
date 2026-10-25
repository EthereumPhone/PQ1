(* Losslessness for the same adaptive byte client in the target proof view. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion PreparedGrind RawSigner.
require import WrapperSession WrapperByteSession WrapperExposureLog ExposureLog ClientQueryLog ForsLeafView.
require import TargetOracleSplit TargetByteView WrapperPlanLossless WrapperReleaseSession WrapperTargetSession WrapperTargetContext.

lemma wrapper_release_session_lossless
  (O <: PrefixOracle {-WrapperSession,-ExposureLog,-ClientQueryLog})
  (F <: ForsLeafOracle {-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  islossless O.hash => islossless O.derive => islossless F.hash => islossless F.leaf => islossless F.secret =>
  islossless WrapperReleaseSession(O,F).sign.
proof.
  move=> oh od fh fl fs; proc; sp 1; if; auto; wp;
    call (wrapper_released_fors_lossless O F oh od fh fl fs); auto.
qed.

lemma wrapper_release_exposure_lossless
  (O <: PrefixOracle {-WrapperSession,-ExposureLog,-ClientQueryLog})
  (F <: ForsLeafOracle {-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  islossless O.hash => islossless O.derive => islossless F.hash => islossless F.leaf => islossless F.secret =>
  islossless WrapperReleaseExposure(O,F).sign.
proof.
  move=> oh od fh fl fs; proc; wp; call (wrapper_release_session_lossless O F oh od fh fl fs); auto.
qed.

lemma wrapper_release_driver_lossless
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog})
  (F <: ForsLeafOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  (forall (V <: WrapperClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless F.hash => islossless F.leaf => islossless F.secret =>
  islossless WrapperReleaseDriver(A,O,F).run.
proof.
  move=> ha oh od fh fl fs; proc; seq 5 : true 1%r 1%r 0%r 0%r => //.
  + call (ha (WrapperReleaseExposure(O,F)) (wrapper_query_hash_lossless O oh)
      (wrapper_release_exposure_lossless O F oh od fh fl fs)); wp; inline WrapperSession(O).init; auto.
  sp 2; if; auto; call (signer_verify_lossless O oh); auto.
qed.

lemma wrapper_release_context_lossless
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog})
  (F <: ForsLeafOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  (forall (V <: WrapperClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless F.hash => islossless F.leaf => islossless F.secret =>
  islossless WrapperReleaseContext(A,O,F).run.
proof.
  move=> ha oh od fh fl fs; have [#] vh vw vf := preparation_view_lossless O oh od.
  proc; call (wrapper_release_driver_lossless A O F ha oh od fh fl fs).
  call (keygen_preparation_lossless (PreparationView(O)) vh vw vf); auto.
qed.

lemma wrapper_target_candidates_lossless
  (A <: WrapperByteClient {-WrapperSession,-ExposureLog,-ClientQueryLog})
  (O <: TargetOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless O.leaf => islossless O.secret =>
  islossless TargetWrapperByteCandidates(A,O).run.
proof.
  move=> ha hh hd hl hs; proc; wp.
  call (wrapper_release_context_lossless (WrapperByteLift(A)) (TargetPrefix(O)) (TargetLeaf(O)) _ hh hd hh hl hs).
  + move=> V hvh hvs; exact (wrapper_byte_lift_lossless A V ha hvh hvs).
  auto.
qed.
