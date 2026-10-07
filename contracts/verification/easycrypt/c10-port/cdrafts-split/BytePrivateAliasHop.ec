(* Charge generated-node aliases while keeping direct adaptive guesses explicit. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenExhaustion RawKeygen FullSession FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision PublicNodeZero.
require import ExposureLog ExposureDriver ExposurePartition ExposurePartitionHop.
require import JointNodeCollision JointMemoOracle BytePrivateAlias ForsValueExposure.
import RealOrder.

lemma byte_exposure_private_alias
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-ExposureLog,
    -JointMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
    private_node_alias Independent.rawhistory Independent.secrethistory] <=
    ((full_physical_budget qr qs)*(full_physical_budget qr qs-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hr hs hraw hsign.
  have he : Pr[IndependentGame(ByteContext(A)).run() @ &m :
      private_node_alias Independent.rawhistory Independent.secrethistory] =
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      private_node_alias Independent.rawhistory Independent.secrethistory].
  + byequiv (byte_exposure_game_projection A) => //.
  rewrite -he; exact (byte_private_node_alias A qr qs &m hr hs hraw hsign).
qed.

lemma byte_aliased_private_opening
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-ExposureLog,
    -JointMemo,-ProjectedSamples}) qr qs seed0 &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
    exists root d secrets, aliased_private_opening Independent.rawhistory Independent.secrethistory
      seed0 root ExposureLog.entries d secrets] <=
    ((full_physical_budget qr qs)*(full_physical_budget qr qs-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hr hs hraw hsign.
  have hc := byte_exposure_private_alias A qr qs &m hr hs hraw hsign.
  have he : Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      exists root d secrets, aliased_private_opening Independent.rawhistory Independent.secrethistory
        seed0 root ExposureLog.entries d secrets] <=
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      private_node_alias Independent.rawhistory Independent.secrethistory].
  + by rewrite Pr[mu_sub]; smt(aliased_opening_implies_private_alias).
  exact (ler_trans _ _ _ he hc).
qed.

lemma byte_private_alias_hop
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
proof.
  move=> ha hr hs hraw hsign hseed.
  have hp := byte_exposure_partition_hop A qr qs seed0 &m ha hr hs hraw hsign hseed.
  have hc := byte_exposure_private_alias A qr qs &m hr hs hraw hsign.
  have he : Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      exists root0, new_message_exposure_partition Independent.rawhistory Independent.secrethistory
        seed0 root0 ExposureLog.entries] <=
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      !private_node_alias Independent.rawhistory Independent.secrethistory /\
      exists root0, new_message_unaliased_partition Independent.rawhistory Independent.secrethistory
        seed0 root0 ExposureLog.entries] +
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      private_node_alias Independent.rawhistory Independent.secrethistory].
  + rewrite Pr[mu_split (!private_node_alias Independent.rawhistory Independent.secrethistory)].
    apply ler_add.
    - by rewrite Pr[mu_sub]; smt(message_partition_without_alias).
    by rewrite Pr[mu_sub]; smt().
  smt().
qed.
