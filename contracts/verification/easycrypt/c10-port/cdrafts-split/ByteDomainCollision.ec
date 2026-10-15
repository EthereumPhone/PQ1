(* Charge public-node collisions in the complete actual byte session. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion FullSession FullSessionCost FullPrefix ByteSession ByteBound.
require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision PublicCollisionState.
import RealOrder.

require import DomainQueryCount DomainNodeCollision DomainMemoOracle DomainCollisionBound DomainSessionCost IndependentWidths.
require import QueryPublicCharges ExposureLog ClientQueryLog ClientQueryDriver.

lemma byte_domain_node_collision
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-Physical,
    -DomainMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ByteContext(A)).run() @ &m : domain_node_collision Independent.rawhistory] <=
    ((node_public_budget qr qs)*(node_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hr hs hraw hsign.
  have hq : 0<=node_public_budget qr qs by exact (node_public_budget_nonnegative qr qs hr hs).
  have hb : hoare [ByteContext(A,Independent).run :
    Independent.queries=[] /\ independent_tables_valid Independent.rawhistory Independent.secrethistory /\ (glob ByteContext(A))=(glob ByteContext(A)){m} ==>
    node_query_count Independent.queries<=node_public_budget qr qs].
  + conseq (domain_byte_context_cost A qr qs hr hs); auto; smt().
  rewrite (independent_domain_collision_observation (ByteContext(A)) &m).
  exact (domain_node_birthday_at_state (ByteContext(A)) (node_public_budget qr qs) &m hq hb).
qed.

lemma query_byte_domain_collision
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-Physical,-DomainMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : domain_node_collision Independent.rawhistory] <=
    ((node_public_budget qr qs)*(node_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hr hs hqr hqs; rewrite -(query_byte_table_projection A domain_node_collision &m).
  exact (byte_domain_node_collision A qr qs &m hr hs hqr hqs).
qed.
