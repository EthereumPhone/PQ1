(* Public collision, zero-sentinel and encoding charges in the same logged
   initialized wrapper byte game. Its budget includes hidden internal work. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import WrapperSession WrapperByteSession WrapperQueryDriver WrapperPrefixBound RawWrapperCost.
require import ExposureLog ClientQueryLog.
require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision PublicCollisionState PublicNodeZero.
require import WotsDigitOrder RawWots EncodingBirthday EncodingMemoOracle MemoEncodingCollision EncodingCollisionState.
require import ByteEncodingCharge QueryPublicCharges.
import RealOrder.

lemma wrapper_byte_query_table_projection
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent})
  (p : (raw_input,digest) fmap -> bool) &m :
  Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : p Independent.rawhistory]=
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : p Independent.rawhistory].
proof.
  have h1 : Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : p Independent.rawhistory]=
      Pr[IndependentGame(WrapperContext(WrapperByteLift(A))).run() @ &m : p Independent.rawhistory].
  + byequiv (_ : ={glob A,glob WrapperLimits,glob KeygenInputs} ==> ={glob Independent}) => //.
    proc; call (wrapper_byte_context_equiv A Independent); inline Independent.init; auto.
  rewrite h1; byequiv (wrapper_query_game_projection (WrapperByteLift(A))) => //.
qed.

lemma wrapper_byte_public_node_collision
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Independent,-Physical,
    -ProjectedMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : public_node_collision Independent.rawhistory] <=
    ((wrapper_total_public_budget qr qs)*(wrapper_total_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hr hs hraw hsign.
  have hq : 0<=wrapper_total_public_budget qr qs by rewrite /wrapper_total_public_budget /wrapper_public_budget /signing_budget; smt().
  have hb : hoare [WrapperByteContext(A,Independent).run :
    Independent.queries=[] /\ (glob WrapperByteContext(A))=(glob WrapperByteContext(A)){m} ==>
    size Independent.queries<=wrapper_total_public_budget qr qs].
  + conseq (wrapper_byte_context_public_cost A qr qs hr hs); auto; smt().
  rewrite (independent_collision_observation (WrapperByteContext(A)) &m).
  exact (public_node_birthday_at_state (WrapperByteContext(A)) (wrapper_total_public_budget qr qs) &m hq hb).
qed.

lemma wrapper_query_byte_public_collision
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-Physical,-ProjectedMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : public_node_collision Independent.rawhistory] <=
    ((wrapper_total_public_budget qr qs)*(wrapper_total_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hr hs hqr hqs; rewrite -(wrapper_byte_query_table_projection A public_node_collision &m).
  exact (wrapper_byte_public_node_collision A qr qs &m hr hs hqr hqs).
qed.
lemma wrapper_byte_public_zero
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Independent,-Physical,-ProjectedMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : public_node_zero Independent.rawhistory] <=
    (wrapper_total_public_budget qr qs)%r*(1%r/2%r)^128.
proof.
  move=> hr hs hqr hqs.
  have hq : 0<=wrapper_total_public_budget qr qs by rewrite /wrapper_total_public_budget /wrapper_public_budget /signing_budget; smt().
  have hb : hoare[WrapperByteContext(A,Independent).run :
    Independent.queries=[] /\ (glob WrapperByteContext(A))=(glob WrapperByteContext(A)){m} ==>
    size Independent.queries<=wrapper_total_public_budget qr qs].
  + conseq (wrapper_byte_context_public_cost A qr qs hr hs); auto; smt().
  rewrite (independent_zero_observation (WrapperByteContext(A)) &m).
  exact (public_node_zero_at_state (WrapperByteContext(A)) (wrapper_total_public_budget qr qs) &m hq hb).
qed.
lemma wrapper_query_byte_public_zero
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-Physical,-ProjectedMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : public_node_zero Independent.rawhistory] <=
    (wrapper_total_public_budget qr qs)%r*(1%r/2%r)^128.
proof.
  move=> hr hs hqr hqs; rewrite -(wrapper_byte_query_table_projection A public_node_zero &m).
  exact (wrapper_byte_public_zero A qr qs &m hr hs hqr hqs).
qed.
lemma wrapper_byte_encoding_collision
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Independent,-Physical,
    -EncodingMemo,-EncodingSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : encoding_public_node_collision Independent.rawhistory] <=
    ((wrapper_total_public_budget qr qs)*(wrapper_total_public_budget qr qs-1))%r/2%r*(1%r/2%r)^129.
proof.
  move=> hr hs hraw hsign.
  have hq : 0<=wrapper_total_public_budget qr qs by rewrite /wrapper_total_public_budget /wrapper_public_budget /signing_budget; smt().
  have hb : hoare [WrapperByteContext(A,Independent).run :
    Independent.queries=[] /\ (glob WrapperByteContext(A))=(glob WrapperByteContext(A)){m} ==>
    size Independent.queries<=wrapper_total_public_budget qr qs].
  + conseq (wrapper_byte_context_public_cost A qr qs hr hs); auto; smt().
  rewrite (encoding_independent_collision_observation (WrapperByteContext(A)) &m).
  exact (encoding_public_node_birthday_at_state (WrapperByteContext(A)) (wrapper_total_public_budget qr qs) &m hq hb).
qed.

lemma wrapper_query_byte_encoding_collision
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Physical,-EncodingMemo,-EncodingSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
    encoding_public_node_collision Independent.rawhistory] <=
    ((wrapper_total_public_budget qr qs)*(wrapper_total_public_budget qr qs-1))%r/2%r*(1%r/2%r)^129.
proof.
  move=> hr hs hraw hsign.
  rewrite -(wrapper_byte_query_table_projection A encoding_public_node_collision &m).
  exact (wrapper_byte_encoding_collision A qr qs &m hr hs hraw hsign).
qed.

lemma wrapper_query_byte_wots_encoding_collision
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Physical,-EncodingMemo,-EncodingSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : wots_encoding_collision Independent.rawhistory] <=
    ((wrapper_total_public_budget qr qs)*(wrapper_total_public_budget qr qs-1))%r/2%r*(1%r/2%r)^129.
proof.
  move=> hr hs hraw hsign.
  have h := wrapper_query_byte_encoding_collision A qr qs &m hr hs hraw hsign.
  have he : Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : wots_encoding_collision Independent.rawhistory] <=
    Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : encoding_public_node_collision Independent.rawhistory].
  + by rewrite Pr[mu_sub]; smt(wots_collision_is_encoding_collision).
  smt().
qed.
