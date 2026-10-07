(* Exact consumer of the complete same-game alias hop. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenExhaustion RawKeygen FullSession FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision PublicNodeZero.
require import ExposureLog ExposureDriver ExposurePartition ExposurePartitionHop.
require import JointNodeCollision JointMemoOracle BytePrivateAlias ForsValueExposure.
import RealOrder.

require import BytePrivateAliasHop.

lemma consume_byte_private_alias_hop
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Physical,-Hybrid,-Shared,
    -Independent,-ExposureLog,-ProjectedMemo,-ProjectedSamples,-JointMemo}) qr qs seed0 &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign =>
    islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  pad (node KeygenInputs.public_seed{m})=seed0 =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <=
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      !private_node_alias Independent.rawhistory Independent.secrethistory /\
      exists root0, new_message_unaliased_partition Independent.rawhistory Independent.secrethistory
        seed0 root0 ExposureLog.entries] +
    ((full_physical_budget qr qs)*(full_physical_budget qr qs-1))%r/2%r*(1%r/2%r)^128 +
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128 +
    (full_public_budget qr qs)%r*(1%r/2%r)^128 +
    (full_public_budget qr qs)%r*(1%r/2%r)^256.
proof. exact (byte_private_alias_hop A qr qs seed0 &m). qed.
