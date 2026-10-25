(* Initialized byte-wrapper projection to the late-opening FORS proof view.
   It preserves the actual result, release ledger and client-query transcript;
   internal cached-query logs need not coincide. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen KeygenPrefixes KeygenExhaustion.
require import RawSigner WrapperSession WrapperByteSession ForsLeafView ExposureLog ClientQueryLog.
require import WrapperQueryDriver WrapperReleaseSession MerkleRootWitness ByteGameTopExtraction.

lemma wrapper_release_context_projection
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  equiv [WrapperQueryContext(A,Independent).run ~ ConcreteWrapperReleaseContext(A,Independent).run :
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
    - conseq (_ : ={glob Independent,glob KeygenInputs} ==> ={res,glob Independent})
        (prepared_top_reference seed0).
      + move=> &1 &2 _ rl rr ql hl sl qr hr sr [he [hw _]].
        split; assumption.
      by sim.
    auto.
  elim* => root0.
  call (wrapper_release_driver_projection A seed0 root0); auto; smt().
qed.

lemma wrapper_release_game_projection
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  equiv [IndependentGame(WrapperQueryContext(A)).run ~ IndependentGame(ConcreteWrapperReleaseContext(A)).run :
    ={glob A,glob WrapperLimits,glob KeygenInputs} ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; call (wrapper_release_context_projection A); inline Independent.init; auto.
qed.

lemma wrapper_byte_release_probability
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) &m :
  Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : res] =
    Pr[IndependentGame(ConcreteWrapperReleaseContext(WrapperByteLift(A))).run() @ &m : res].
proof.
  have h := wrapper_byte_query_probability A &m.
  have he : Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res] =
      Pr[IndependentGame(ConcreteWrapperReleaseContext(WrapperByteLift(A))).run() @ &m : res]
    by byequiv (wrapper_release_game_projection (WrapperByteLift(A))) => //.
  smt().
qed.
