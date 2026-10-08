(* Budget the low-129-bit collision experiment at the actual initial client state. *)
require import AllCore List StdOrder.
require import C10RawOracle PrefixGuess PrefixIdeal RawKeygen.
require import EncodingBirthday MemoEncodingCollision EncodingMemoOracle EncodingCollisionGame.
import RField RealOrder.

lemma encoding_collision_budget_at_state (A <: PrefixContext {-Independent}) q &m :
  hoare [A(Independent).run : Independent.queries=[] /\ (glob A)=(glob A){m} ==>
    size Independent.queries<=q] =>
  hoare [IndependentEncodingCollision(A).run : (glob A)=(glob A){m} ==>
    size Independent.queries<=q].
proof. move=> hb; proc; call hb; inline Independent.init; auto. qed.

lemma encoding_public_node_birthday_at_state
  (A <: PrefixContext {-Independent,-EncodingMemo,-EncodingSamples}) q &m :
  0<=q =>
  hoare [A(Independent).run : Independent.queries=[] /\ (glob A)=(glob A){m} ==>
    size Independent.queries<=q] =>
  Pr[IndependentEncodingCollision(A).run() @ &m : res] <=
    (q*(q-1))%r/2%r*(1%r/2%r)^129.
proof.
  move=> hq hb.
  have he : Pr[IndependentEncodingCollision(A).run() @ &m : res] <=
    Pr[EncodingGame(EncodingDraws(A)).run() @ &m :
      size EncodingSamples.nodes<=q /\ !uniq EncodingSamples.nodes].
  + byequiv (_ : ={glob A} /\ (glob A){1}=(glob A){m} ==>
      res{1} => size EncodingSamples.nodes{2}<=q /\ !uniq EncodingSamples.nodes{2}) => //.
    conseq (encoding_public_collision_refinement A)
      (encoding_collision_budget_at_state A q &m hb) (encoding_public_draws_recorded A);
      rewrite /encoding_memo_nodes_valid; smt(encoding_recorded_collision_implies_repeat).
  have hp := encoding_projected_birthday (EncodingDraws(A)) q &m hq.
  exact (ler_trans _ _ _ he hp).
qed.

lemma encoding_independent_collision_observation
  (A <: PrefixContext {-Independent}) &m :
  Pr[IndependentGame(A).run() @ &m : encoding_public_node_collision Independent.rawhistory] =
  Pr[IndependentEncodingCollision(A).run() @ &m : res].
proof.
  byequiv (_ : ={glob A} ==>
    encoding_public_node_collision Independent.rawhistory{1}=res{2}) => //.
  proc; call (_ : ={glob Independent}); 1,2: by sim.
  inline Independent.init; auto.
qed.
