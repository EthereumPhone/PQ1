(* Discharge the alias budget using all calls of the actual initialized byte game. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixIdeal KeygenExhaustion.
require import RawKeygen FullSession FullPrefix ByteSession.
require import ProjectedBirthday JointNodeCollision JointMemoOracle JointCallCost PrivateAliasBound.
import RealOrder.

lemma byte_context_joint_cost
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-JointMemo,-ProjectedSamples}) qr qs :
  0<=qr => 0<=qs =>
  hoare [ByteContext(A,JointMemo(ProjectedSamples)).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\ JointMemo.calls=0 ==>
    JointMemo.calls<=full_physical_budget qr qs].
proof.
  move=> hr hs.
  conseq (byte_context_equiv A (JointMemo(ProjectedSamples)))
    (full_context_joint_cost (ByteLift(A)) qr qs hr hs).
  + move=> &m hm; exists (glob A){m} qr qs 0 JointMemo.queries{m} JointMemo.rawhistory{m}
      JointMemo.secrethistory{m} KeygenInputs.message{m} KeygenInputs.public_seed{m}
      KeygenInputs.random{m} ProjectedSamples.nodes{m}; smt().
  by rewrite /full_physical_budget; smt().
qed.

lemma byte_private_node_alias
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-JointMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ByteContext(A)).run() @ &m :
    private_node_alias Independent.rawhistory Independent.secrethistory] <=
    ((full_physical_budget qr qs)*(full_physical_budget qr qs-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hr hs hraw hsign.
  have hq : 0<=full_physical_budget qr qs by rewrite /full_physical_budget /signing_budget; smt().
  have hb : hoare [ByteContext(A,JointMemo(ProjectedSamples)).run :
    JointMemo.calls=0 /\ (glob ByteContext(A))=(glob ByteContext(A)){m} ==>
    JointMemo.calls<=full_physical_budget qr qs].
  + conseq (byte_context_joint_cost A qr qs hr hs); auto; smt().
  exact (private_alias_at_state (ByteContext(A)) (full_physical_budget qr qs) &m hq hb).
qed.
