(* Budget the collision experiment at the actual initial client state. *)
require import AllCore List StdOrder.
require import C10RawOracle PrefixGuess PrefixIdeal RawKeygen.
require import ProjectedBirthday DomainNodeCollision NodeQueryDomain DomainQueryCount DomainNodeTable IndependentWidths DomainMemoOracle DomainCollisionGame.
import RField RealOrder.

lemma domain_collision_budget_at_state (A <: PrefixContext {-Independent}) q &m :
  hoare [A(Independent).run : Independent.queries=[] /\ independent_tables_valid Independent.rawhistory Independent.secrethistory /\ (glob A)=(glob A){m} ==>
    node_query_count Independent.queries<=q] =>
  hoare [IndependentDomainCollision(A).run : (glob A)=(glob A){m} ==>
    node_query_count Independent.queries<=q].
proof. move=> hb; proc; call hb; inline Independent.init; auto;
  rewrite /independent_tables_valid /valid_history; smt(FMap.emptyE). qed.

lemma domain_node_birthday_at_state
  (A <: PrefixContext {-Independent,-DomainMemo,-ProjectedSamples}) q &m :
  0<=q =>
  hoare [A(Independent).run : Independent.queries=[] /\ independent_tables_valid Independent.rawhistory Independent.secrethistory /\ (glob A)=(glob A){m} ==>
    node_query_count Independent.queries<=q] =>
  Pr[IndependentDomainCollision(A).run() @ &m : res] <=
    (q*(q-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hq hb.
  have he : Pr[IndependentDomainCollision(A).run() @ &m : res] <=
    Pr[ProjectedGame(DomainPublicDraws(A)).run() @ &m :
      size ProjectedSamples.nodes<=q /\ !uniq ProjectedSamples.nodes].
  + byequiv (_ : ={glob A} /\ (glob A){1}=(glob A){m} ==>
      res{1} => size ProjectedSamples.nodes{2}<=q /\ !uniq ProjectedSamples.nodes{2}) => //.
    conseq (domain_collision_refinement A)
      (domain_collision_budget_at_state A q &m hb) (domain_public_draws_recorded A);
      rewrite /domain_memo_nodes_valid; smt(domain_collision_implies_repeat).
  have hp := projected_birthday (DomainPublicDraws(A)) q &m hq.
  exact (ler_trans _ _ _ he hp).
qed.

lemma independent_domain_collision_observation
  (A <: PrefixContext {-Independent}) &m :
  Pr[IndependentGame(A).run() @ &m : domain_node_collision Independent.rawhistory] =
  Pr[IndependentDomainCollision(A).run() @ &m : res].
proof.
  byequiv (_ : ={glob A} ==>
    domain_node_collision Independent.rawhistory{1}=res{2}) => //.
  proc; call (_ : ={glob Independent}); 1,2: by sim.
  inline Independent.init; auto.
qed.
