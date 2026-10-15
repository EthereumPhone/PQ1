require import AllCore List StdOrder.
require import C10RawOracle PrefixGuess PrefixIdeal RawKeygen.
require import ProjectedBirthday DomainNodeCollision NodeQueryDomain DomainQueryCount DomainNodeTable IndependentWidths DomainMemoOracle DomainCollisionGame.
import RField RealOrder.
require import DomainCollisionBound.

lemma checked (A <: PrefixContext {-Independent,-DomainMemo,-ProjectedSamples}) q &m :
  0<=q =>
  hoare [A(Independent).run : Independent.queries=[] /\ independent_tables_valid Independent.rawhistory Independent.secrethistory /\ (glob A)=(glob A){m} ==>
    node_query_count Independent.queries<=q+1] =>
  Pr[IndependentDomainCollision(A).run() @ &m : res] <=
    (q*(q-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hq hb; exact (domain_node_birthday_at_state A q &m hq hb).
qed.
