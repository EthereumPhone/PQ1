(* Existing verifier extraction with its new-message guard tied to the full output log. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen FullSession ByteSession ExposureLog ExposureDriver ExposureSupport.
require import ExposureAccounting ExposureGameHistory SessionForestExtraction ByteGameForestExtraction.
require import MemoNodeCollision PublicNodeZero.

lemma byte_exposure_projection_reverse
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) :
  equiv [IndependentGame(ExposureContext(ByteLift(A))).run ~ IndependentGame(ByteContext(A)).run :
    ={glob A,glob FullLimits,glob KeygenInputs} ==> ={res,glob A,glob Independent,glob FullSession}].
proof. symmetry; conseq (byte_exposure_game_projection A); smt(). qed.

lemma byte_exposure_forest_extraction
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) seed0 :
  hoare [IndependentGame(ExposureContext(ByteLift(A))).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists root0, new_message_forest_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 FullSession.signed_messages].
proof.
  conseq (byte_exposure_projection_reverse A) (byte_game_forest_extraction A seed0).
  + move=> &m hm; exists (glob A){m} FullLimits.raw_cap{m} FullLimits.sign_cap{m}
      KeygenInputs.message{m} KeygenInputs.public_seed{m} KeygenInputs.random{m}; smt().
  smt().
qed.

lemma byte_exposure_forgery_accounted
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) seed0 qs0 :
  0<=qs0 =>
  hoare [IndependentGame(ExposureContext(ByteLift(A))).run :
    FullLimits.sign_cap=qs0 /\ pad (node KeygenInputs.public_seed)=seed0 ==>
    size ExposureLog.entries<=qs0 /\
    exposure_messages ExposureLog.entries=FullSession.signed_messages /\
    exposures_supported Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries /\
    (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists root0, new_message_forest_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 (exposure_messages ExposureLog.entries))].
proof.
  move=> hqs; conseq (byte_exposure_game_history A qs0 hqs) (byte_exposure_forest_extraction A seed0);
    rewrite /exposure_accounting; smt().
qed.
