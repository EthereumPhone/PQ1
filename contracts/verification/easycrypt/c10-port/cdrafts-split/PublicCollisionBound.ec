(* Whole-run birthday charge for distinct retained public inputs. *)
require import AllCore List StdOrder.
require import C10RawOracle PrefixGuess RawKeygen.
require import ProjectedBirthday MemoNodeCollision ProjectedMemoOracle PublicCollisionGame.
import RField RealOrder.

lemma public_node_birthday
  (A <: PrefixContext {-Independent,-ProjectedMemo,-ProjectedSamples}) q &m :
  0<=q =>
  hoare [A(Independent).run : Independent.queries=[] ==> size Independent.queries<=q] =>
  Pr[IndependentNodeCollision(A).run() @ &m : res] <=
    (q*(q-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hq hb.
  have he : Pr[IndependentNodeCollision(A).run() @ &m : res] <=
    Pr[ProjectedGame(PublicDraws(A)).run() @ &m :
      size ProjectedSamples.nodes<=q /\ !uniq ProjectedSamples.nodes].
  + byequiv (_ : ={glob A} ==>
      res{1} => size ProjectedSamples.nodes{2}<=q /\ !uniq ProjectedSamples.nodes{2}) => //.
    conseq (public_collision_refinement A)
      (independent_collision_budget A q hb) (public_draws_recorded A);
      rewrite /memo_nodes_valid; smt(recorded_collision_implies_repeat).
  have hp := projected_birthday (PublicDraws(A)) q &m hq.
  exact (ler_trans _ _ _ he hp).
qed.
