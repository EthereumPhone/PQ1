(* Termination and the exact twelve-candidate byte-client consumer. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion PreparedGrind.
require import RawSigner FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import ForsLeafView LeafForestView LeafSignerView LeafSessionView LeafViewLossless TargetOracleSplit TargetByteView.

lemma query_exposure_hash_lossless
  (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) :
  islossless O.hash => islossless QueryExposureSession(O).hash.
proof. move=> hh; proc; call (full_hash_lossless O hh); if; auto. qed.

lemma leaf_session_sign_lossless
  (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog})
  (F <: ForsLeafOracle {-FullSession,-ExposureLog,-ClientQueryLog}) :
  islossless O.hash => islossless O.derive =>
  islossless F.hash => islossless F.leaf => islossless F.secret => islossless LeafSession(O,F).sign.
proof.
  move=> oh od fh fl fs; proc; sp 1; if; auto; wp;
    call (leaf_signer_sign_lossless O F oh od fh fl fs); auto.
qed.
lemma leaf_exposure_sign_lossless
  (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog})
  (F <: ForsLeafOracle {-FullSession,-ExposureLog,-ClientQueryLog}) :
  islossless O.hash => islossless O.derive =>
  islossless F.hash => islossless F.leaf => islossless F.secret => islossless LeafExposureSession(O,F).sign.
proof.
  move=> oh od fh fl fs; proc; wp; call (leaf_session_sign_lossless O F oh od fh fl fs); auto.
qed.
lemma leaf_query_driver_lossless
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog})
  (F <: ForsLeafOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  (forall (V <: FullClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive =>
  islossless F.hash => islossless F.leaf => islossless F.secret => islossless LeafQueryDriver(A,O,F).run.
proof.
  move=> ha oh od fh fl fs; proc; seq 5 : true 1%r 1%r 0%r 0%r => //.
  + call (ha (LeafExposureSession(O,F)) (query_exposure_hash_lossless O oh)
      (leaf_exposure_sign_lossless O F oh od fh fl fs)); wp; inline FullSession(O).init; auto.
  sp 2; if; auto; call (signer_verify_lossless O oh); auto.
qed.
lemma leaf_query_context_lossless
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog})
  (F <: ForsLeafOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  (forall (V <: FullClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive =>
  islossless F.hash => islossless F.leaf => islossless F.secret => islossless LeafQueryContext(A,O,F).run.
proof.
  move=> ha oh od fh fl fs; have [#] vh vw vf := preparation_view_lossless O oh od.
  proc; call (leaf_query_driver_lossless A O F ha oh od fh fl fs).
  call (keygen_preparation_lossless (PreparationView(O)) vh vw vf); auto.
qed.
lemma target_byte_candidates_lossless
  (A <: ByteClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: TargetOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless O.leaf => islossless O.secret =>
  islossless TargetByteCandidates(A,O).run.
proof.
  move=> ha hh hd hl hs; proc; wp.
  call (leaf_query_context_lossless (ByteLift(A)) (TargetPrefix(O)) (TargetLeaf(O)) _ hh hd hh hl hs).
  + move=> V hvh hvs; exact (byte_lift_lossless A V ha hvh hvs).
  auto.
qed.
