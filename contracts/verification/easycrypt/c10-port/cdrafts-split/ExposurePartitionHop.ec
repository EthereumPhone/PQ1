(* Refine the explicit residual in the same initialized game. The remaining
   returned-coordinate cases are not charged here and this is not a closed EUF bound. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion RawKeygen FullSession FullSessionCost FullPrefix ByteSession ByteBound.
require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision PublicNodeZero BytePublicNodeBad.
require import ExposureLog ExposureDriver ExposurePartition ExposurePartitionGame.
import RealOrder.

lemma byte_exposure_partition_hop
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Physical,-Hybrid,-Shared,
    -Independent,-ExposureLog,-ProjectedMemo,-ProjectedSamples}) qr qs seed0 &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign =>
    islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  pad (node KeygenInputs.public_seed{m})=seed0 =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <=
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      exists root0, new_message_exposure_partition Independent.rawhistory Independent.secrethistory
        seed0 root0 ExposureLog.entries] +
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128 +
    (full_public_budget qr qs)%r*(1%r/2%r)^128 +
    (full_public_budget qr qs)%r*(1%r/2%r)^256.
proof.
  move=> ha hr hs hraw hsign hseed.
  have hp := byte_public_node_bad_hop A qr qs &m ha hr hs hraw hsign.
  have hproj : Pr[IndependentGame(ByteContext(A)).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory] =
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory].
  + byequiv (byte_exposure_game_projection A) => //.
  have hz : Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      !(exists root0, new_message_exposure_partition Independent.rawhistory Independent.secrethistory
        seed0 root0 ExposureLog.entries)] = 0%r.
  + byphoare (_ : FullLimits.sign_cap=qs /\ pad (node KeygenInputs.public_seed)=seed0 ==>
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      !(exists root0, new_message_exposure_partition Independent.rawhistory Independent.secrethistory
        seed0 root0 ExposureLog.entries)) => //.
    hoare; conseq (byte_exposure_partition A seed0 qs hs); smt().
  have he : Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory] <=
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      exists root0, new_message_exposure_partition Independent.rawhistory Independent.secrethistory
        seed0 root0 ExposureLog.entries] +
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      !(exists root0, new_message_exposure_partition Independent.rawhistory Independent.secrethistory
        seed0 root0 ExposureLog.entries)].
  + rewrite Pr[mu_split (exists root0, new_message_exposure_partition Independent.rawhistory Independent.secrethistory
        seed0 root0 ExposureLog.entries)]; apply ler_add;
      by rewrite Pr[mu_sub]; smt().
  smt().
qed.
