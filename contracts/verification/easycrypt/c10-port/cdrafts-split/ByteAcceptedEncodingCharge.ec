(* The accepted-encoding charge in the same initialized byte game. *)
require import AllCore List FMap StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import FullSession FullPrefix ByteSession BytePublicCollision.
require import ExposureLog ExposureDriver ClientQueryLog ClientQueryDriver.
require import EncodingMemoOracle AcceptedWotsCollision AcceptedEncodingPool AcceptedEncodingGame AcceptedEncodingCharge FullDigestPrefixSampling.
import RealOrder.

lemma byte_accepted_encoding_collision
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-Physical,
    -EncodingMemo,-FullDigestSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ByteContext(A)).run() @ &m : accepted_wots_encoding_collision Independent.rawhistory] <=
    accepted_encoding_charge (full_public_budget qr qs).
proof.
  move=> hr hs hraw hsign.
  have hq : 0<=full_public_budget qr qs by rewrite /full_public_budget /signing_budget; smt().
  have hb : hoare [ByteContext(A,Independent).run :
    Independent.queries=[] /\ (glob ByteContext(A))=(glob ByteContext(A)){m} ==>
    size Independent.queries<=full_public_budget qr qs].
  + conseq (byte_context_public_cost A qr qs hr hs); auto; smt().
  rewrite (accepted_independent_collision_observation (ByteContext(A)) &m).
  exact (accepted_encoding_birthday_at_state (ByteContext(A)) (full_public_budget qr qs) &m hq hb).
qed.

lemma query_byte_accepted_encoding_collision
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Physical,-EncodingMemo,-FullDigestSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    accepted_wots_encoding_collision Independent.rawhistory] <=
    accepted_encoding_charge (full_public_budget qr qs).
proof.
  move=> hr hs hraw hsign.
  have h1 : Pr[IndependentGame(ByteContext(A)).run() @ &m : accepted_wots_encoding_collision Independent.rawhistory] =
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m : accepted_wots_encoding_collision Independent.rawhistory].
  + byequiv (byte_exposure_game_projection A) => //.
  have h2 : Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m : accepted_wots_encoding_collision Independent.rawhistory] =
    Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : accepted_wots_encoding_collision Independent.rawhistory].
  + byequiv (byte_query_exposure_game_projection A) => //.
  rewrite -h2 -h1; exact (byte_accepted_encoding_collision A qr qs &m hr hs hraw hsign).
qed.
