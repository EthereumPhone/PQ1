(* Actual initialized ordinary byte-game addressed-collision bound. No client
   query, honest-query freshness, success, or desired budget premise is added. *)
require import AllCore List Distr FSet FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion FullSession ByteSession.
require import ExposureLog ClientQueryLog ClientQueryDriver QueryPublicCharges.
require import DomainNodeCollision DomainQueryCount DomainSessionCost DomainMemoOracle ByteDomainCollision ProjectedBirthday.
require import AddressedNodeCollision AddressedBuckets AddressedBucketBudget AddressedAudit AddressedCollisionBound AddressedSessionExceptionCount.
import RField RealOrder.

op addressed_node_charge qr qs =
  (exceptional_public_budget qr qs)%r*(exceptional_public_budget qr qs+1)%r*(1%r/2%r)^128.
op retained_domain_node_charge qr qs =
  ((node_public_budget qr qs)*(node_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128.
op best_addressed_node_charge qr qs = if retained_domain_node_charge qr qs<=addressed_node_charge qr qs
  then retained_domain_node_charge qr qs else addressed_node_charge qr qs.

lemma byte_addressed_node_collision
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-AddressedAudit}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ByteContext(A)).run() @ &m : addressed_node_collision Independent.rawhistory]
    <=addressed_node_charge qr qs.
proof.
  move=> hr hs hqr hqs.
  have hq : 0<=exceptional_public_budget qr qs by rewrite /exceptional_public_budget; smt().
  have hk : 0<=exceptional_public_budget qr qs+1 by smt().
  have hb : hoare [IndependentGame(ByteContext(A)).run :
    (glob ByteContext(A))=(glob ByteContext(A)){m} ==>
    addressed_excess Independent.rawhistory<=exceptional_public_budget qr qs /\
    forall label, card (addressed_bucket Independent.rawhistory label)<=exceptional_public_budget qr qs+1].
  + conseq (byte_game_addressed_bucket_budget A qr qs hr hs); auto; smt().
  exact (addressed_collision_bound_at_state (ByteContext(A)) (exceptional_public_budget qr qs)
    (exceptional_public_budget qr qs+1) &m hq hk hb).
qed.

lemma query_byte_addressed_collision
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-AddressedAudit}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : addressed_node_collision Independent.rawhistory]
    <=addressed_node_charge qr qs.
proof.
  move=> hr hs hqr hqs; rewrite -(query_byte_table_projection A addressed_node_collision &m).
  exact (byte_addressed_node_collision A qr qs &m hr hs hqr hqs).
qed.

lemma query_byte_addressed_collision_best
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-AddressedAudit,
    -Physical,-DomainMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : addressed_node_collision Independent.rawhistory]
    <=best_addressed_node_charge qr qs.
proof.
  move=> hr hs hqr hqs.
  have hn := query_byte_addressed_collision A qr qs &m hr hs hqr hqs.
  have hd := query_byte_domain_collision A qr qs &m hr hs hqr hqs.
  have hsub : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : addressed_node_collision Independent.rawhistory] <=
    Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : domain_node_collision Independent.rawhistory].
  + by rewrite Pr[mu_sub]; smt(addressed_collision_is_domain).
  rewrite /best_addressed_node_charge /retained_domain_node_charge; smt().
qed.
