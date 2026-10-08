(* Public collision and zero-sentinel charges in the common logged byte game. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import FullSession FullPrefix ByteSession BytePublicCollision ExposureLog ExposureDriver ClientQueryLog ClientQueryDriver.
require import MemoNodeCollision PublicNodeZero ProjectedBirthday ProjectedMemoOracle.
import RealOrder.

lemma independent_zero_observation (C <: PrefixContext {-Independent}) &m :
  Pr[IndependentGame(C).run() @ &m : public_node_zero Independent.rawhistory]=
    Pr[IndependentNodeZero(C).run() @ &m : res].
proof.
  byequiv (_ : ={glob C} ==> public_node_zero Independent.rawhistory{1}=res{2}) => //.
  proc; call (_ : ={glob Independent}); first 2 by sim.
  inline Independent.init; auto.
qed.

lemma query_byte_table_projection
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent})
  (p : (raw_input,digest) fmap -> bool) &m :
  Pr[IndependentGame(ByteContext(A)).run() @ &m : p Independent.rawhistory]=
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : p Independent.rawhistory].
proof.
  have h1 : Pr[IndependentGame(ByteContext(A)).run() @ &m : p Independent.rawhistory]=
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m : p Independent.rawhistory]
    by byequiv (byte_exposure_game_projection A) => //.
  rewrite h1; byequiv (byte_query_exposure_game_projection A) => //.
qed.
lemma query_byte_success_projection
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) &m :
  Pr[IndependentGame(ByteContext(A)).run() @ &m : res]=
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res].
proof.
  have h1 : Pr[IndependentGame(ByteContext(A)).run() @ &m : res]=
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m : res]
    by byequiv (byte_exposure_game_projection A) => //.
  rewrite h1; byequiv (byte_query_exposure_game_projection A) => //.
qed.
lemma query_byte_public_collision
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-Physical,-ProjectedMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : public_node_collision Independent.rawhistory] <=
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hr hs hqr hqs; rewrite -(query_byte_table_projection A public_node_collision &m).
  exact (byte_public_node_collision A qr qs &m hr hs hqr hqs).
qed.
lemma byte_public_zero
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-Physical,-ProjectedMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ByteContext(A)).run() @ &m : public_node_zero Independent.rawhistory] <=
    (full_public_budget qr qs)%r*(1%r/2%r)^128.
proof.
  move=> hr hs hqr hqs.
  have hq : 0<=full_public_budget qr qs by rewrite /full_public_budget /signing_budget; smt().
  have hb : hoare[ByteContext(A,Independent).run :
    Independent.queries=[] /\ (glob ByteContext(A))=(glob ByteContext(A)){m} ==>
    size Independent.queries<=full_public_budget qr qs].
  + conseq (byte_context_public_cost A qr qs hr hs); auto; smt().
  rewrite (independent_zero_observation (ByteContext(A)) &m).
  exact (public_node_zero_at_state (ByteContext(A)) (full_public_budget qr qs) &m hq hb).
qed.
lemma query_byte_public_zero
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-Physical,-ProjectedMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : public_node_zero Independent.rawhistory] <=
    (full_public_budget qr qs)%r*(1%r/2%r)^128.
proof.
  move=> hr hs hqr hqs; rewrite -(query_byte_table_projection A public_node_zero &m).
  exact (byte_public_zero A qr qs &m hr hs hqr hqs).
qed.
