(* Same byte-game forgery residual, excluding both collisions and the zero node. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion FullSession FullSessionCost FullPrefix ByteSession ByteBound.
require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision BytePublicCollision PublicNodeZero.
import RealOrder.

lemma independent_zero_observation (A <: PrefixContext {-Independent}) &m :
  Pr[IndependentGame(A).run() @ &m : public_node_zero Independent.rawhistory] =
  Pr[IndependentNodeZero(A).run() @ &m : res].
proof.
  byequiv (_ : ={glob A} ==> public_node_zero Independent.rawhistory{1}=res{2}) => //.
  proc; call (_ : ={glob Independent}); 1,2: by sim.
  inline Independent.init; auto.
qed.

lemma byte_public_node_zero
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-Physical,
    -ProjectedMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ByteContext(A)).run() @ &m : public_node_zero Independent.rawhistory] <=
    (full_public_budget qr qs)%r*(1%r/2%r)^128.
proof.
  move=> hr hs hraw hsign.
  have hq : 0<=full_public_budget qr qs by rewrite /full_public_budget /signing_budget; smt().
  have hb : hoare [ByteContext(A,Independent).run :
    Independent.queries=[] /\ (glob ByteContext(A))=(glob ByteContext(A)){m} ==>
    size Independent.queries<=full_public_budget qr qs].
  + conseq (byte_context_public_cost A qr qs hr hs); auto; smt().
  rewrite (independent_zero_observation (ByteContext(A)) &m).
  exact (public_node_zero_at_state (ByteContext(A)) (full_public_budget qr qs) &m hq hb).
qed.

lemma byte_public_node_bad_hop
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Physical,-Hybrid,-Shared,
    -Independent,-ProjectedMemo,-ProjectedSamples}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign =>
    islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <=
    Pr[IndependentGame(ByteContext(A)).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory] +
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128 +
    (full_public_budget qr qs)%r*(1%r/2%r)^128 +
    (full_public_budget qr qs)%r*(1%r/2%r)^256.
proof.
  move=> ha hr hs hraw hsign.
  have hp := byte_public_collision_hop A qr qs &m ha hr hs hraw hsign.
  have hz := byte_public_node_zero A qr qs &m hr hs hraw hsign.
  have hsplit : Pr[IndependentGame(ByteContext(A)).run() @ &m : res /\ !public_node_collision Independent.rawhistory] <=
    Pr[IndependentGame(ByteContext(A)).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory] +
    Pr[IndependentGame(ByteContext(A)).run() @ &m : public_node_zero Independent.rawhistory].
  + rewrite Pr[mu_split (!public_node_zero Independent.rawhistory)]; apply ler_add;
      by rewrite Pr[mu_sub]; smt().
  smt().
qed.
