(* Accepted-encoding collisions in the original initialized wrapper game.
   The query budget includes every admitted internal signing attempt. *)
require import AllCore List FMap StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import WrapperSession WrapperByteSession WrapperQueryDriver WrapperPrefixBound RawWrapperCost.
require import ExposureLog ClientQueryLog WrapperPublicCharges.
require import EncodingMemoOracle AcceptedWotsCollision AcceptedEncodingPool AcceptedEncodingGame AcceptedEncodingCharge FullDigestPrefixSampling.
import RealOrder.

lemma wrapper_byte_accepted_encoding_collision
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Independent,-Physical,
    -EncodingMemo,-FullDigestSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : accepted_wots_encoding_collision Independent.rawhistory] <=
    accepted_encoding_charge (wrapper_total_public_budget qr qs).
proof.
  move=> hr hs hraw hsign.
  have hq : 0<=wrapper_total_public_budget qr qs by rewrite /wrapper_total_public_budget /wrapper_public_budget /signing_budget; smt().
  have hb : hoare [WrapperByteContext(A,Independent).run :
    Independent.queries=[] /\ (glob WrapperByteContext(A))=(glob WrapperByteContext(A)){m} ==>
    size Independent.queries<=wrapper_total_public_budget qr qs].
  + conseq (wrapper_byte_context_public_cost A qr qs hr hs); auto; smt().
  rewrite (accepted_independent_collision_observation (WrapperByteContext(A)) &m).
  exact (accepted_encoding_birthday_at_state (WrapperByteContext(A)) (wrapper_total_public_budget qr qs) &m hq hb).
qed.

lemma wrapper_query_byte_accepted_encoding_collision
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Physical,-EncodingMemo,-FullDigestSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
    accepted_wots_encoding_collision Independent.rawhistory] <=
    accepted_encoding_charge (wrapper_total_public_budget qr qs).
proof.
  move=> hr hs hraw hsign.
  rewrite -(wrapper_byte_query_table_projection A accepted_wots_encoding_collision &m).
  exact (wrapper_byte_accepted_encoding_collision A qr qs &m hr hs hraw hsign).
qed.
