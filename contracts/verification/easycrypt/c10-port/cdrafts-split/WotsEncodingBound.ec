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

lemma original_byte_conditional_encoding_bound (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-Physical,-EncodingMemo,-FullDigestSamples,-WotsMemo,-WotsAcceptedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : selected_accepted_collision Independent.rawhistory]<=conditional_encoding_charge (qr+4*qs+2).
proof.
  move=> hr hs hqr hqs.
  have hz : Pr[WotsMemoGame(ClientQueryContext(ByteLift(A))).run() @ &m : !(WotsMemo.accepted_calls<=(qr+4*qs+2))]=0%r.
  + byphoare (_ : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==> _) => //.
    hoare; conseq (wots_census_byte_count A qr qs hr hs); smt().
  have hb := wots_game_conditional_collision_bound (ClientQueryContext(ByteLift(A))) (qr+4*qs+2) &m _; first smt().
  have hsub : Pr[WotsMemoGame(ClientQueryContext(ByteLift(A))).run() @ &m : selected_accepted_collision WotsMemo.rawhistory] <=
    Pr[WotsMemoGame(ClientQueryContext(ByteLift(A))).run() @ &m :
      (WotsMemo.accepted_calls<=(qr+4*qs+2) /\ selected_accepted_collision WotsMemo.rawhistory) \/
      !(WotsMemo.accepted_calls<=(qr+4*qs+2))].
  + rewrite Pr[mu_sub]; smt().
  have he : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : selected_accepted_collision Independent.rawhistory]=
    Pr[WotsMemoGame(ClientQueryContext(ByteLift(A))).run() @ &m : selected_accepted_collision WotsMemo.rawhistory].
  + byequiv (wots_game_projection (ClientQueryContext(ByteLift(A)))) => //; smt().
  rewrite he; move: hsub; rewrite Pr[mu_or] hz; smt(ge0_mu).
qed.

lemma original_byte_best_wots_encoding_bound (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-Physical,-EncodingMemo,-FullDigestSamples,-WotsMemo,-WotsAcceptedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : selected_accepted_collision Independent.rawhistory]<=
    best_wots_encoding_charge (full_public_budget qr qs) (qr+4*qs+2).
proof.
  move=> hr hs hqr hqs.
  have hc := original_byte_conditional_encoding_bound A qr qs &m hr hs hqr hqs.
  have ho := query_byte_accepted_encoding_collision A qr qs &m hr hs hqr hqs.
  have hsub : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : selected_accepted_collision Independent.rawhistory]<=
    Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : accepted_wots_encoding_collision Independent.rawhistory].
  + rewrite Pr[mu_sub]; smt(selected_collision_is_accepted).
  rewrite /best_wots_encoding_charge; smt().
qed.
