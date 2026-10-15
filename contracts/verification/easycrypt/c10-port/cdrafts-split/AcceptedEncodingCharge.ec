(* Accepted encoding-collision bound at the actual initial client state. *)
require import AllCore List StdOrder.
require import C10RawOracle PrefixGuess PrefixIdeal RawKeygen.
require import EncodingMemoOracle EncodingCollisionGame.
require import AcceptedWotsCollision AcceptedEncodingPool AcceptedEncodingMemo AcceptedEncodingGame FullDigestPrefixSampling.
import RField RealOrder.

lemma accepted_collision_budget_at_state (A <: PrefixContext {-Independent}) q &m :
  hoare [A(Independent).run : Independent.queries=[] /\ (glob A)=(glob A){m} ==>
    size Independent.queries<=q] =>
  hoare [IndependentAcceptedEncodingCollision(A).run : (glob A)=(glob A){m} ==>
    size Independent.queries<=q].
proof. move=> hb; proc; call hb; inline Independent.init; auto. qed.

lemma accepted_encoding_birthday_at_state
  (A <: PrefixContext {-Independent,-EncodingMemo,-FullDigestSamples}) q &m :
  0<=q =>
  hoare [A(Independent).run : Independent.queries=[] /\ (glob A)=(glob A){m} ==>
    size Independent.queries<=q] =>
  Pr[IndependentAcceptedEncodingCollision(A).run() @ &m : res] <=
    accepted_encoding_charge q.
proof.
  move=> hq hb.
  have he : Pr[IndependentAcceptedEncodingCollision(A).run() @ &m : res] <=
    Pr[FullDigestGame(EncodingDraws(A)).run() @ &m :
      size FullDigestSamples.nodes<=q /\ accepted_encoding_pool_collision FullDigestSamples.nodes].
  + byequiv (_ : ={glob A} /\ (glob A){1}=(glob A){m} ==>
      res{1} => size FullDigestSamples.nodes{2}<=q /\ accepted_encoding_pool_collision FullDigestSamples.nodes{2}) => //.
    conseq (accepted_public_collision_refinement A)
      (accepted_collision_budget_at_state A q &m hb) (accepted_public_draws_recorded A);
      rewrite /accepted_memo_nodes_valid /accepted_table_records /accepted_encoding_pool_collision; smt().
  have hp := adaptive_accepted_encoding_bound (EncodingDraws(A)) q &m hq.
  exact (ler_trans _ _ _ he hp).
qed.

lemma accepted_independent_collision_observation
  (A <: PrefixContext {-Independent}) &m :
  Pr[IndependentGame(A).run() @ &m : accepted_wots_encoding_collision Independent.rawhistory] =
  Pr[IndependentAcceptedEncodingCollision(A).run() @ &m : res].
proof.
  byequiv (_ : ={glob A} ==>
    accepted_wots_encoding_collision Independent.rawhistory{1}=res{2}) => //.
  proc; call (_ : ={glob Independent}); 1,2: by sim.
  inline Independent.init; auto.
qed.
