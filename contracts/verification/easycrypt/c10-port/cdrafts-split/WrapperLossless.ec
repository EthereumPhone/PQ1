(* Termination of the existing wrapper schedule and retry-capable session.
   Oracle and adaptive-client losslessness are explicit; successful signing,
   readiness and final release are not hypotheses. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import KeygenExhaustion PreparedGrind RawSigner RawWrapper WrapperSession.

lemma raw_wrapper_lossless (O <: PrefixOracle) :
  islossless O.hash => islossless O.derive => islossless RawWrapper(O).sign.
proof.
  move=> hh hd; proc; sp 1; if; last by auto.
  seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (signer_sign_lossless O hh hd); auto.
  if; last by auto.
  seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (signer_sign_lossless O hh hd); auto.
  if; auto; wp; call (signer_verify_lossless O hh); auto.
qed.

lemma wrapper_hash_lossless (O <: PrefixOracle {-WrapperSession}) :
  islossless O.hash => islossless WrapperSession(O).hash.
proof. move=> hh; proc; sp 1; if; auto; wp; call hh; auto. qed.

lemma wrapper_sign_lossless (O <: PrefixOracle {-WrapperSession}) :
  islossless O.hash => islossless O.derive => islossless WrapperSession(O).sign.
proof.
  move=> hh hd; proc; sp 1; if; auto; wp;
    call (raw_wrapper_lossless O hh hd); auto.
qed.

lemma wrapper_driver_lossless
  (A <: WrapperClient {-WrapperSession})
  (O <: PrefixOracle {-A,-WrapperSession}) :
  (forall (V <: WrapperClientOracle {-A}),
    islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless WrapperDriver(A,O).run.
proof.
  move=> ha hh hd; proc; seq 2 : true 1%r 1%r 0%r 0%r => //.
  + call (ha (WrapperSession(O)) (wrapper_hash_lossless O hh)
      (wrapper_sign_lossless O hh hd)); inline WrapperSession(O).init; auto.
  sp 1; if; auto; call (signer_verify_lossless O hh); auto.
qed.

lemma wrapper_context_lossless
  (A <: WrapperClient {-WrapperSession})
  (O <: PrefixOracle {-A,-WrapperSession}) :
  (forall (V <: WrapperClientOracle {-A}),
    islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless WrapperContext(A,O).run.
proof.
  move=> ha hh hd; have [#] hvh hvw hvf := preparation_view_lossless O hh hd.
  proc; call (wrapper_driver_lossless A O ha hh hd).
  call (keygen_preparation_lossless (PreparationView(O)) hvh hvw hvf); auto.
qed.
