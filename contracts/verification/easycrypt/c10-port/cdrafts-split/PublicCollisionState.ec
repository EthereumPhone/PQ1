(* Budget the collision experiment at the actual initial client state. *)
require import AllCore List StdOrder.
require import C10RawOracle PrefixGuess PrefixIdeal RawKeygen.
require import ProjectedBirthday MemoNodeCollision ProjectedMemoOracle PublicCollisionGame.
import RField RealOrder.

lemma collision_budget_at_state (A <: PrefixContext {-Independent}) q &m :
  hoare [A(Independent).run : Independent.queries=[] /\ (glob A)=(glob A){m} ==>
    size Independent.queries<=q] =>
  hoare [IndependentNodeCollision(A).run : (glob A)=(glob A){m} ==>
    size Independent.queries<=q].
proof. move=> hb; proc; call hb; inline Independent.init; auto. qed.

lemma public_node_birthday_at_state
  (A <: PrefixContext {-Independent,-ProjectedMemo,-ProjectedSamples}) q &m :
  0<=q =>
  hoare [A(Independent).run : Independent.queries=[] /\ (glob A)=(glob A){m} ==>
    size Independent.queries<=q] =>
  Pr[IndependentNodeCollision(A).run() @ &m : res] <=
    (q*(q-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hq hb.
  have he : Pr[IndependentNodeCollision(A).run() @ &m : res] <=
    Pr[ProjectedGame(PublicDraws(A)).run() @ &m :
      size ProjectedSamples.nodes<=q /\ !uniq ProjectedSamples.nodes].
  + byequiv (_ : ={glob A} /\ (glob A){1}=(glob A){m} ==>
      res{1} => size ProjectedSamples.nodes{2}<=q /\ !uniq ProjectedSamples.nodes{2}) => //.
    conseq (public_collision_refinement A)
      (collision_budget_at_state A q &m hb) (public_draws_recorded A);
      rewrite /memo_nodes_valid; smt(recorded_collision_implies_repeat).
  have hp := projected_birthday (PublicDraws(A)) q &m hq.
  exact (ler_trans _ _ _ he hp).
qed.

lemma independent_collision_observation
  (A <: PrefixContext {-Independent}) &m :
  Pr[IndependentGame(A).run() @ &m : public_node_collision Independent.rawhistory] =
  Pr[IndependentNodeCollision(A).run() @ &m : res].
proof.
  byequiv (_ : ={glob A} ==>
    public_node_collision Independent.rawhistory{1}=res{2}) => //.
  proc; call (_ : ={glob Independent}); 1,2: by sim.
  inline Independent.init; auto.
qed.
