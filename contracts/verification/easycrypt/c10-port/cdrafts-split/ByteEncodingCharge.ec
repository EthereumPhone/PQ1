(* A numerical encoding-collision charge in the original initialized byte game. *)
require import AllCore List FMap StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import FullSession FullPrefix ByteSession BytePublicCollision.
require import ExposureLog ExposureDriver ClientQueryLog ClientQueryDriver.
require import WotsDigitOrder RawWots EncodingBirthday EncodingMemoOracle MemoEncodingCollision EncodingCollisionState.
import RealOrder.

op wots_encoding_collision (h : (raw_input,digest) fmap) =
  exists x y d e, x<>y /\ h.[x]=Some d /\ h.[y]=Some e /\ raw_digits d=raw_digits e.

lemma wots_collision_is_encoding_collision h :
  wots_encoding_collision h => encoding_public_node_collision h.
proof.
  rewrite /wots_encoding_collision /encoding_public_node_collision.
  move=> [x y d e [hne [hd [he hc]]]]; exists x y d e.
  smt(equal_raw_digits_encoding).
qed.

lemma byte_encoding_collision
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-Physical,
    -EncodingMemo,-EncodingSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ByteContext(A)).run() @ &m : encoding_public_node_collision Independent.rawhistory] <=
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r/2%r*(1%r/2%r)^129.
proof.
  move=> hr hs hraw hsign.
  have hq : 0<=full_public_budget qr qs by rewrite /full_public_budget /signing_budget; smt().
  have hb : hoare [ByteContext(A,Independent).run :
    Independent.queries=[] /\ (glob ByteContext(A))=(glob ByteContext(A)){m} ==>
    size Independent.queries<=full_public_budget qr qs].
  + conseq (byte_context_public_cost A qr qs hr hs); auto; smt().
  rewrite (encoding_independent_collision_observation (ByteContext(A)) &m).
  exact (encoding_public_node_birthday_at_state (ByteContext(A)) (full_public_budget qr qs) &m hq hb).
qed.

lemma query_byte_encoding_collision
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Physical,-EncodingMemo,-EncodingSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    encoding_public_node_collision Independent.rawhistory] <=
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r/2%r*(1%r/2%r)^129.
proof.
  move=> hr hs hraw hsign.
  have h1 : Pr[IndependentGame(ByteContext(A)).run() @ &m : encoding_public_node_collision Independent.rawhistory] =
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m : encoding_public_node_collision Independent.rawhistory].
  + byequiv (byte_exposure_game_projection A) => //.
  have h2 : Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m : encoding_public_node_collision Independent.rawhistory] =
    Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : encoding_public_node_collision Independent.rawhistory].
  + byequiv (byte_query_exposure_game_projection A) => //.
  rewrite -h2 -h1; exact (byte_encoding_collision A qr qs &m hr hs hraw hsign).
qed.

lemma query_byte_wots_encoding_collision
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Physical,-EncodingMemo,-EncodingSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : wots_encoding_collision Independent.rawhistory] <=
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r/2%r*(1%r/2%r)^129.
proof.
  move=> hr hs hraw hsign.
  have h := query_byte_encoding_collision A qr qs &m hr hs hraw hsign.
  have he : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : wots_encoding_collision Independent.rawhistory] <=
    Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : encoding_public_node_collision Independent.rawhistory].
  + by rewrite Pr[mu_sub]; smt(wots_collision_is_encoding_collision).
  smt().
qed.
