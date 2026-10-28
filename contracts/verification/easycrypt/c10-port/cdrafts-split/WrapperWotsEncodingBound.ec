(* Conditional-pool encoding charge in the original initialized byte game. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import FullSession FullPrefix ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import WrapperSession WrapperByteSession WrapperQueryDriver WrapperPrefixBound.
require import EncodingMemoOracle FullDigestPrefixSampling AcceptedWotsCollision AcceptedEncodingPool.
require import ByteAcceptedEncodingCharge WrapperAcceptedEncodingCharge.
require import WotsAcceptedPrefix WotsAcceptedPool WotsMemoOracle WotsPoolGame WotsByteCount.
require import WotsConditionalCollision WotsEncodingCharge SelectedWotsCollision.
import RealOrder.

lemma wrapper_byte_conditional_encoding_bound (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-Physical,-EncodingMemo,-FullDigestSamples,-WotsMemo,-WotsAcceptedSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : selected_accepted_collision Independent.rawhistory]<=conditional_encoding_charge (qr+10*qs+2).
proof.
  move=> hr hs hqr hqs.
  have hz : Pr[WotsMemoGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : !(WotsMemo.accepted_calls<=(qr+10*qs+2))]=0%r.
  + byphoare (_ : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==> _) => //.
    hoare; conseq (wots_census_wrapper_byte_count A qr qs hr hs); smt().
  have hb := wots_game_conditional_collision_bound (WrapperQueryContext(WrapperByteLift(A))) (qr+10*qs+2) &m _; first smt().
  have hsub : Pr[WotsMemoGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : selected_accepted_collision WotsMemo.rawhistory] <=
    Pr[WotsMemoGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
      (WotsMemo.accepted_calls<=(qr+10*qs+2) /\ selected_accepted_collision WotsMemo.rawhistory) \/
      !(WotsMemo.accepted_calls<=(qr+10*qs+2))].
  + rewrite Pr[mu_sub]; smt().
  have he : Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : selected_accepted_collision Independent.rawhistory]=
    Pr[WotsMemoGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : selected_accepted_collision WotsMemo.rawhistory].
  + byequiv (wots_game_projection (WrapperQueryContext(WrapperByteLift(A)))) => //; smt().
  rewrite he; move: hsub; rewrite Pr[mu_or] hz; smt(ge0_mu).
qed.

lemma wrapper_byte_best_wots_encoding_bound (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-Physical,-EncodingMemo,-FullDigestSamples,-WotsMemo,-WotsAcceptedSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : selected_accepted_collision Independent.rawhistory]<=
    best_wots_encoding_charge (wrapper_total_public_budget qr qs) (qr+10*qs+2).
proof.
  move=> hr hs hqr hqs.
  have hc := wrapper_byte_conditional_encoding_bound A qr qs &m hr hs hqr hqs.
  have ho := wrapper_query_byte_accepted_encoding_collision A qr qs &m hr hs hqr hqs.
  have hsub : Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : selected_accepted_collision Independent.rawhistory]<=
    Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : accepted_wots_encoding_collision Independent.rawhistory].
  + rewrite Pr[mu_sub]; smt(selected_collision_is_accepted).
  rewrite /best_wots_encoding_charge; smt().
qed.
