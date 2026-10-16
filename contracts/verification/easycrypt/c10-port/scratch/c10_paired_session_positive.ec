(* Paired computations through the actual adaptive byte session. The comparison
   shares the original session state and preserves admission, failure and the
   returned-message ledger. This is an EasyCrypt relation, not a Rust theorem. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawSigner RawSignature RawDecode FullSession ByteSession.
require import C10OuterCallerBridge C10SearchAcceptance C10DigestCallers.

module PairedSession (O : PrefixOracle) = {
  proc init = FullSession(O).init
  proc hash = FullSession(O).hash
  proc sign(random message shuffle : raw_input) : raw_signature option = {
    var result; result <- None;
    if (!FullSession.failed /\ size message = 32 /\
        (size random = 0 \/ size random = 16) /\ size shuffle = 32 /\
        FullSession.sign_calls < FullSession.sign_limit) {
      result <@ PairedDigestSigner(O).sign(FullSession.seed,FullSession.root,random,message,shuffle);
      FullSession.sign_calls <- FullSession.sign_calls+1;
      if (result <> None) {
        FullSession.signed_messages <- rcons FullSession.signed_messages message;
      } else { FullSession.failed <- true; }
    }
    return result;
  }
}.

module PairedByteDriver (A : ByteClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    PairedSession(O).init(seed,root,qr,qs);
    forged <@ A(ByteView(PairedSession(O))).run(seed,root);
    result <- false;
    if (!FullSession.failed /\ size forged.`1 = 32 /\ byte_values forged.`1 /\
        byte_signature forged.`2 /\ !List.mem FullSession.signed_messages forged.`1) {
      result <@ PairedDigestSigner(O).verify(seed,root,forged.`1,decode_signature forged.`2);
    }
    return result;
  }
}.

module PairedByteContext (A : ByteClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ PairedByteDriver(A,O).run(inputs.`3,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.

lemma paired_session_hash :
  equiv[FullSession(Physical).hash ~ PairedSession(Physical).hash :
    ={arg,glob FullSession,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob FullSession,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; sp 1 1; if; first by auto.
  + by wp; call physical_hash_paired; auto.
  by auto.
qed.

lemma paired_session_sign :
  equiv[FullSession(Physical).sign ~ PairedSession(Physical).sign :
    ={arg,glob FullSession,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob FullSession,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; sp 1 1; if; first by auto.
  + by wp; call raw_signer_sign_digest; auto.
  by auto.
qed.

lemma paired_byte_view_sign :
  equiv[ByteView(FullSession(Physical)).sign ~ ByteView(PairedSession(Physical)).sign :
    ={arg,glob FullSession,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob FullSession,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; sp 1 1; if; first by auto.
  + by wp; call paired_session_sign; auto.
  by auto.
qed.

lemma paired_byte_client (A <: ByteClient {-FullSession,-Physical,-Shared}) :
  equiv[A(ByteView(FullSession(Physical))).run ~ A(ByteView(PairedSession(Physical))).run :
    ={arg,glob A,glob FullSession,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob A,glob FullSession,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc (={glob FullSession,glob Physical} /\ valid_history Shared.history{1}) => //.
  + by conseq paired_session_hash.
  by conseq paired_byte_view_sign; smt().
qed.

lemma paired_byte_driver (A <: ByteClient {-FullSession,-Physical,-Shared}) :
  equiv[ByteDriver(A,Physical).run ~ PairedByteDriver(A,Physical).run :
    ={arg,glob A,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob A,glob FullSession,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; seq 2 2 : (={seed,root,qr,qs,forged,glob A,glob FullSession,glob Physical} /\
    valid_history Shared.history{1}).
  + call (paired_byte_client A); inline FullSession(Physical).init; by auto.
  sp 1 1; if; first by auto.
  + call raw_signer_verify_digest; auto => /> &m hh hf hm hb hs hv hn.
    exact (outer_decoded_counters forged{m}.`2 hs).
  by auto.
qed.
