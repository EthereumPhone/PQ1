(* Accumulated response accounting in the same initialized byte experiment. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner FullSession ByteSession.
require import ExposureLog ExposureDriver ExposureSupport ExposureAccounting ExposureSessionHistory.

lemma exposure_context_history
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) qs0 :
  0<=qs0 =>
  hoare [ExposureContext(A,Independent).run : FullLimits.sign_cap=qs0 ==>
    exposures_supported Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries /\
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls qs0].
proof.
  move=> hqs; proc; seq 1 : (FullLimits.sign_cap=qs0).
  + call (_ : true ==> true); first by trivial. auto.
  exists* inputs; elim* => inputs0.
  call (exposure_driver_history A inputs0.`3 inputs0.`4 qs0 hqs); auto; smt().
qed.

lemma byte_exposure_game_history
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) qs0 :
  0<=qs0 =>
  hoare [IndependentGame(ExposureContext(ByteLift(A))).run : FullLimits.sign_cap=qs0 ==>
    exposures_supported Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries /\
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls qs0].
proof.
  move=> hqs; proc; call (exposure_context_history (ByteLift(A)) qs0 hqs); inline Independent.init; auto.
qed.

lemma byte_exposure_count
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) qs0 :
  0<=qs0 =>
  hoare [IndependentGame(ExposureContext(ByteLift(A))).run : FullLimits.sign_cap=qs0 ==>
    size ExposureLog.entries<=qs0 /\
    exposure_messages ExposureLog.entries=FullSession.signed_messages /\
    (forall message signature, List.mem ExposureLog.entries (message,signature) =>
      exposure_supported Independent.rawhistory Independent.secrethistory
        FullSession.seed FullSession.root (message,signature))].
proof.
  move=> hqs; conseq (byte_exposure_game_history A qs0 hqs);
    rewrite /exposure_accounting /exposures_supported; smt().
qed.
