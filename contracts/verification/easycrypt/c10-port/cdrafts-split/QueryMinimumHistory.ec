(* The common initialized byte game retains both minimal counts and complete openings. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import FullSession ByteSession ExposureLog ExposureDriver ClientQueryLog ClientQueryDriver.
require import ExposureSupport ExposureAccounting ExposureGameHistory MinimumExposureSupport MinimumExposureGame.

lemma byte_exposure_canonical_history
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) qs0 :
  0<=qs0 =>
  hoare [IndependentGame(ExposureContext(ByteLift(A))).run : FullLimits.sign_cap=qs0 ==>
    exposures_supported Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries /\
    minimum_entries Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries /\
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls qs0].
proof.
  move=> hqs; conseq (byte_exposure_game_history A qs0 hqs)
    (minimum_byte_exposure_game_history A qs0 hqs); smt().
qed.

lemma query_byte_canonical_history
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs0 :
  0<=qs0 =>
  hoare [IndependentGame(ClientQueryContext(ByteLift(A))).run : FullLimits.sign_cap=qs0 ==>
    exposures_supported Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries /\
    minimum_entries Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries /\
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls qs0].
proof.
  move=> hqs.
  have he : equiv [IndependentGame(ClientQueryContext(ByteLift(A))).run ~
    IndependentGame(ExposureContext(ByteLift(A))).run :
    ={glob A,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob Independent,glob FullSession,glob ExposureLog}]
    by symmetry; conseq (byte_query_exposure_game_projection A); smt().
  conseq he (byte_exposure_canonical_history A qs0 hqs).
  + move=> &m hm; exists (glob A){m} FullLimits.raw_cap{m} FullLimits.sign_cap{m}
      KeygenInputs.message{m} KeygenInputs.public_seed{m} KeygenInputs.random{m}; smt().
  smt().
qed.
