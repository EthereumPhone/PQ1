(* Discharge the valid-history invariant from the actual initialization and
   key preparation. The paired experiment preserves the same success event. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames KeygenPrefixes KeygenExhaustion.
require import FullSession ByteSession C10SearchAcceptance C10PairedSession.

lemma paired_preparation_wots :
  equiv[PreparationView(Physical).wots ~ PreparationView(Physical).wots :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof. by proc; call physical_derive_paired; auto. qed.

lemma paired_preparation_fors :
  equiv[PreparationView(Physical).fors ~ PreparationView(Physical).fors :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof. by proc; call physical_derive_paired; auto. qed.

lemma paired_preparation (P <: Preparation {-Physical,-Shared}) :
  equiv[P(PreparationView(Physical)).run ~ P(PreparationView(Physical)).run :
    ={glob P,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob P,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc (={glob Physical} /\ valid_history Shared.history{1}) => //.
  + by conseq physical_hash_paired.
  + by conseq paired_preparation_wots.
  by conseq paired_preparation_fors.
qed.

lemma paired_byte_context
  (A <: ByteClient {-FullSession,-Physical,-Shared,-FullLimits,-KeygenInputs}) :
  equiv[ByteContext(A,Physical).run ~ PairedByteContext(A,Physical).run :
    ={glob A,glob FullLimits,glob KeygenInputs,glob Physical} /\
    valid_history Shared.history{1} ==>
    ={res,glob A,glob FullSession,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; call (paired_byte_driver A); call (paired_preparation KeygenPreparation); by auto.
qed.

lemma paired_byte_initialized
  (A <: ByteClient {-FullSession,-Physical,-Shared,-FullLimits,-KeygenInputs}) :
  equiv[RealGame(ByteContext(A)).run ~ RealGame(PairedByteContext(A)).run :
    ={glob A,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob FullSession,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; call (paired_byte_context A); inline Shared.init; auto.
  by rewrite /valid_history; smt(emptyE).
qed.

lemma paired_byte_success_probability
  (A <: ByteClient {-FullSession,-Physical,-Shared,-FullLimits,-KeygenInputs}) &m :
  Pr[RealGame(PairedByteContext(A)).run() @ &m : res] =
  Pr[RealGame(ByteContext(A)).run() @ &m : res].
proof.
  byequiv (_ : ={glob A,glob FullLimits,glob KeygenInputs} ==> ={res}) => //.
  symmetry; conseq (paired_byte_initialized A); smt().
qed.
