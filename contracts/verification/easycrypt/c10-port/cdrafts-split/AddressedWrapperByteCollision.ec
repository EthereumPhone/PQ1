(* Addressed collisions in the actual initialized wrapper byte game. The
   smaller of the old public-node charge and the derived address charge is used. *)
require import AllCore List Distr FSet FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import WrapperSession WrapperByteSession WrapperQueryDriver WrapperPrefixBound RawWrapperCost.
require import ExposureLog ClientQueryLog WrapperPublicCharges.
require import MemoNodeCollision DomainNodeCollision ProjectedMemoOracle ProjectedBirthday.
require import AddressedNodeCollision AddressedBuckets AddressedAudit AddressedCollisionBound.
require import AddressedWrapperMemoSession AddressedWrapperBucketBudget.
import RField RealOrder.

op wrapper_addressed_node_charge qr qs =
  (wrapper_exceptional_public_budget qr qs)%r*(wrapper_exceptional_public_budget qr qs+1)%r*(1%r/2%r)^128.
op retained_wrapper_node_charge qr qs =
  ((wrapper_total_public_budget qr qs)*(wrapper_total_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128.
op best_wrapper_addressed_node_charge qr qs =
  if retained_wrapper_node_charge qr qs<=wrapper_addressed_node_charge qr qs
  then retained_wrapper_node_charge qr qs else wrapper_addressed_node_charge qr qs.

lemma wrapper_byte_addressed_node_collision
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Independent,-AddressedAudit}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : addressed_node_collision Independent.rawhistory]
    <=wrapper_addressed_node_charge qr qs.
proof.
  move=> hr hs hqr hqs.
  have hq : 0<=wrapper_exceptional_public_budget qr qs by rewrite /wrapper_exceptional_public_budget; smt().
  have hk : 0<=wrapper_exceptional_public_budget qr qs+1 by smt().
  have hb : hoare [IndependentGame(WrapperByteContext(A)).run :
    (glob WrapperByteContext(A))=(glob WrapperByteContext(A)){m} ==>
    addressed_excess Independent.rawhistory<=wrapper_exceptional_public_budget qr qs /\
    forall label, card (addressed_bucket Independent.rawhistory label)<=wrapper_exceptional_public_budget qr qs+1].
  + conseq (wrapper_byte_game_addressed_bucket_budget A qr qs hr hs); auto; smt().
  exact (addressed_collision_bound_at_state (WrapperByteContext(A)) (wrapper_exceptional_public_budget qr qs)
    (wrapper_exceptional_public_budget qr qs+1) &m hq hk hb).
qed.

lemma wrapper_query_byte_addressed_collision
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-AddressedAudit}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : addressed_node_collision Independent.rawhistory]
    <=wrapper_addressed_node_charge qr qs.
proof.
  move=> hr hs hqr hqs; rewrite -(wrapper_byte_query_table_projection A addressed_node_collision &m).
  exact (wrapper_byte_addressed_node_collision A qr qs &m hr hs hqr hqs).
qed.

lemma wrapper_query_byte_addressed_collision_best
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-AddressedAudit,
    -Physical,-ProjectedMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : addressed_node_collision Independent.rawhistory]
    <=best_wrapper_addressed_node_charge qr qs.
proof.
  move=> hr hs hqr hqs.
  have hn := wrapper_query_byte_addressed_collision A qr qs &m hr hs hqr hqs.
  have hp := wrapper_query_byte_public_collision A qr qs &m hr hs hqr hqs.
  have hsub : Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : addressed_node_collision Independent.rawhistory] <=
    Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : public_node_collision Independent.rawhistory].
  + by rewrite Pr[mu_sub]; smt(addressed_collision_is_domain domain_collision_is_public).
  rewrite /best_wrapper_addressed_node_charge /retained_wrapper_node_charge; smt().
qed.
