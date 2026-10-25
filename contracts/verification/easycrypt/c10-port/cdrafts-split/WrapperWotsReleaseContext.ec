(* Initialized byte-wrapper projection to the release-only WOTS view,
   preserving actual results, released-output ledger and client-query log. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen KeygenPrefixes KeygenExhaustion.
require import RawSigner WrapperSession WrapperByteSession ChainValueView ChainSessionView ExposureLog ClientQueryLog.
require import WrapperQueryDriver WrapperWotsReleaseSession MerkleRootWitness ByteGameTopExtraction.

lemma wrapper_wots_release_context_projection
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  equiv [WrapperQueryContext(A,Independent).run ~ ConcreteWrapperWotsReleaseContext(A,Independent).run :
    ={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs} ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; exists* (pad (node KeygenInputs.public_seed{1})); elim* => seed0.
  seq 1 1 : (={inputs,glob A,glob Independent,glob WrapperLimits} /\
    exists root0, inputs{1}.`3=seed0 /\ inputs{1}.`4=pad root0 /\
      merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0).
  + call (_ : ={glob Independent,glob KeygenInputs} /\ pad (node KeygenInputs.public_seed{1})=seed0 ==>
      ={res,glob Independent} /\ exists root0, res{1}.`3=seed0 /\ res{1}.`4=pad root0 /\
        merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0).
    - conseq (chain_preparation_projection Independent) (prepared_top_reference seed0); smt().
    auto.
  elim* => root0.
  call (wrapper_wots_release_driver_projection A seed0 root0); auto; smt().
qed.

lemma wrapper_wots_release_game_projection
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  equiv [IndependentGame(WrapperQueryContext(A)).run ~ IndependentGame(ConcreteWrapperWotsReleaseContext(A)).run :
    ={glob A,glob WrapperLimits,glob KeygenInputs} ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; call (wrapper_wots_release_context_projection A); inline Independent.init; auto.
qed.

lemma wrapper_byte_wots_release_probability
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) &m :
  Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : res] =
    Pr[IndependentGame(ConcreteWrapperWotsReleaseContext(WrapperByteLift(A))).run() @ &m : res].
proof.
  have h := wrapper_byte_query_probability A &m.
  have he : Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res] =
      Pr[IndependentGame(ConcreteWrapperWotsReleaseContext(WrapperByteLift(A))).run() @ &m : res]
    by byequiv (wrapper_wots_release_game_projection (WrapperByteLift(A))) => //.
  smt().
qed.
