(* Refine the explicit residual in the same initialized game. The remaining
   top-opening event is not charged here and this is not a closed EUF bound. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion RawKeygen FullSession FullSessionCost FullPrefix ByteSession ByteBound.
require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision PublicNodeZero BytePublicNodeBad.
require import SessionTopExtraction ByteGameTopExtraction.
import RealOrder.

lemma byte_top_opening_hop
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Physical,-Hybrid,-Shared,
    -Independent,-ProjectedMemo,-ProjectedSamples}) qr qs seed0 &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign =>
    islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  pad (node KeygenInputs.public_seed{m})=seed0 =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <=
    Pr[IndependentGame(ByteContext(A)).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      exists root0, new_message_top_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 FullSession.signed_messages] +
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128 +
    (full_public_budget qr qs)%r*(1%r/2%r)^128 +
    (full_public_budget qr qs)%r*(1%r/2%r)^256.
proof.
  move=> ha hr hs hraw hsign hseed.
  have hp := byte_public_node_bad_hop A qr qs &m ha hr hs hraw hsign.
  have hz : Pr[IndependentGame(ByteContext(A)).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      !(exists root0, new_message_top_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 FullSession.signed_messages)] = 0%r.
  + byphoare (_ : pad (node KeygenInputs.public_seed)=seed0 ==>
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      !(exists root0, new_message_top_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 FullSession.signed_messages)) => //.
    hoare; conseq (byte_game_top_extraction A seed0); smt().
  have he : Pr[IndependentGame(ByteContext(A)).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory] <=
    Pr[IndependentGame(ByteContext(A)).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      exists root0, new_message_top_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 FullSession.signed_messages] +
    Pr[IndependentGame(ByteContext(A)).run() @ &m :
      res /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      !(exists root0, new_message_top_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 FullSession.signed_messages)].
  + rewrite Pr[mu_split (exists root0, new_message_top_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 FullSession.signed_messages)]; apply ler_add;
      by rewrite Pr[mu_sub]; smt().
  smt().
qed.
