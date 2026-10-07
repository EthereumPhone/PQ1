(* Exact consumers of the observer's original-game projection and budget. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixIdeal KeygenExhaustion FullSession ByteSession.
require import ExposureLog ExposureDriver ClientQueryLog ClientQueryDriver ClientGuessCandidates.

lemma consume_byte_query_projection
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  equiv [IndependentGame(ExposureContext(ByteLift(A))).run ~
    IndependentGame(ClientQueryContext(ByteLift(A))).run :
    ={glob A,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob Independent,glob FullSession,glob ExposureLog}].
proof. exact (byte_query_exposure_game_projection A). qed.

lemma consume_byte_query_budget
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qr :
  hoare [ClientQueryContext(ByteLift(A),Independent).run : FullLimits.raw_cap=qr /\ 0<=qr ==>
    size (client_guess_candidates ClientQueryLog.inputs ClientQueryLog.output.`2)<=qr].
proof. exact (client_game_candidate_bound (ByteLift(A)) Independent qr). qed.
