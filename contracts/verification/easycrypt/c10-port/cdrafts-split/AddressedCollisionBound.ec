(* Every actual addressed collision is observed when the derived final memo
   buckets fit the observer cap. The cap never changes oracle computation. *)
require import AllCore List Distr FSet FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixIdeal.
require import AddressedNodeCollision AddressedBuckets AddressedBucketHistory AddressedAudit AddressedAuditBound.
import RField RealOrder.

lemma addressed_collision_bound_at_state
  (A <: PrefixContext {-Independent,-AddressedAudit}) q k0 &m :
  0<=q => 0<=k0 =>
  hoare [IndependentGame(A).run : (glob A)=(glob A){m} ==>
    addressed_excess Independent.rawhistory<=q /\
    forall label, card (addressed_bucket Independent.rawhistory label)<=k0] =>
  Pr[IndependentGame(A).run() @ &m : addressed_node_collision Independent.rawhistory]
    <=q%r*k0%r*(1%r/2%r)^128.
proof.
  move=> hq hk hb.
  have he : Pr[IndependentGame(A).run() @ &m : addressed_node_collision Independent.rawhistory] <=
    Pr[AddressedAuditGame(A).run(k0) @ &m : AddressedAudit.bad /\ AddressedAudit.calls<=q].
  + byequiv (_ : ={glob A} /\ (glob A){1}=(glob A){m} /\ k{2}=k0 ==>
      addressed_node_collision Independent.rawhistory{1} => AddressedAudit.bad{2} /\ AddressedAudit.calls{2}<=q) => //.
    conseq (addressed_audit_game_projection A k0) hb (addressed_audit_game_invariant A k0);
      rewrite /addressed_audit_invariant /oversized_bucket; smt(addressed_collision_label).
  have hp := addressed_audit_collision_bound A q k0 &m hq hk.
  exact (ler_trans _ _ _ he hp).
qed.
