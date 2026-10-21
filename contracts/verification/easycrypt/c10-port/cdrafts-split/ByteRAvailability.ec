(* The original byte adapter reaches the complete R-observed experiment.
   Its forgery result and full session/oracle state erase exactly; the new
   probability bound concerns nonce exhaustion, not all signing failures. *)
require import AllCore List Distr FMap StdOrder StdBigop.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames.
require import KeygenPrefixes KeygenExhaustion FullSession ByteSession FullPrefix.
require import RObservedSigner FullRBound FullRGame FullRInitialization.
require import GrindTail GrindExhaustion SessionClosedForm.
import RField RealOrder Bigreal BRA.

lemma byte_r_context_erases (A <: ByteClient {-FullSession,-RFailure,-FullLimits,-KeygenInputs})
    (O <: PrefixOracle {-A,-FullSession,-RFailure,-FullLimits,-KeygenInputs}) :
  equiv[ByteContext(A,O).run ~ FullRContext(ByteLift(A),O).run :
    ={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob O,glob FullSession}].
proof.
  transitivity FullContext(ByteLift(A),O).run
    (={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
      ={res,glob A,glob O,glob FullSession})
    (={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
      ={res,glob A,glob O,glob FullSession}) => //.
  + smt().
  + exact (byte_context_equiv A O).
  exact (full_r_context_erases (ByteLift(A)) O).
qed.

lemma byte_r_initialized_erases
    (A <: ByteClient {-FullSession,-RFailure,-Physical,-Shared,-FullLimits,-KeygenInputs}) :
  equiv[RealGame(ByteContext(A)).run ~ RealGame(FullRContext(ByteLift(A))).run :
    ={glob A,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob FullSession,glob Physical}].
proof.
  proc; call (byte_r_context_erases A Physical); inline Shared.init; auto.
qed.

lemma byte_r_forgery_probability_unchanged
    (A <: ByteClient {-FullSession,-RFailure,-Physical,-Shared,-FullLimits,-KeygenInputs}) &m :
  Pr[RealGame(FullRContext(ByteLift(A))).run() @ &m : res] =
    Pr[RealGame(ByteContext(A)).run() @ &m : res].
proof.
  byequiv (_ : ={glob A,glob FullLimits,glob KeygenInputs} ==> ={res}) => //.
  symmetry; conseq (byte_r_initialized_erases A); smt().
qed.

op byte_r_availability_charge qr qs =
  qs%r * (reject_mass^signing_budget +
    ((signing_budget*(155135+qr+qs*full_r_sign_cost))%r +
      (signing_budget*(signing_budget-1))%r/2%r) * (1%r/2%r)^128) +
    (full_public_budget qr qs)%r * (1%r/2%r)^256.

lemma byte_r_initialized_exhaustion
    (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-RFailure,-Physical,-Hybrid,-Shared,-Independent})
    qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0 <= qr => 0 <= qs => FullLimits.raw_cap{m} = qr => FullLimits.sign_cap{m} = qs =>
  Pr[RealGame(FullRFailureContext(ByteLift(A))).run() @ &m : res] <=
    byte_r_availability_charge qr qs.
proof.
  move=> ha hqr hqs hraw hsign.
  have hll : forall (V <: FullClientOracle {-ByteLift(A)}),
    islossless V.hash => islossless V.sign => islossless ByteLift(A,V).run.
  + move=> V hh hs; exact (byte_lift_lossless A V ha hh hs).
  have h := full_r_initialized_physical (ByteLift(A)) qr qs &m hll hqr hqs hraw hsign.
  move: h; rewrite Bigreal.sumri_const 1:hqs /= /exhaustion_charge revisit_closed.
  by rewrite /byte_r_availability_charge.
qed.
