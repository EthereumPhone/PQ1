require import AllCore List FMap C10RawOracle RawSigner RawSignature RawDecode FullSession ByteSession C10FixedBackend C10FixedCallerBridge C10OuterCallerBridge C10FunctionalObservations C10FunctionalSignatureBytes C10Representation C10RepresentationBridge KeygenPrefixes KeygenExhaustion C10FunctionalKeygen.

(* Adaptive byte sessions projected to fixed-backend functional values.
   The library game's failure latch is absorbing. This is deliberately not
   the secure wrapper's retry-after-refusal model or a Rust client extraction. *)





module FunctionalSession = {
  proc init = FullSession(FixedPrefix).init
  proc hash(x : raw_input) : digest = {
    var result; result <- nseq 256 false;
    if (FullSession.raw_calls < FullSession.raw_limit) {
      result <@ FunctionalValues.hash(x);
      FullSession.raw_calls <- FullSession.raw_calls+1;
    }
    return result;
  }
  proc sign(random message shuffle : raw_input) : raw_signature option = {
    var result; result <- None;
    if (!FullSession.failed /\ size message = 32 /\
        (size random = 0 \/ size random = 16) /\ size shuffle = 32 /\
        FullSession.sign_calls < FullSession.sign_limit) {
      result <@ FunctionalValues.sign(FullSession.seed,FullSession.root,random,message,shuffle);
      FullSession.sign_calls <- FullSession.sign_calls+1;
      if (result <> None) {
        FullSession.signed_messages <- rcons FullSession.signed_messages message;
      } else { FullSession.failed <- true; }
    }
    return result;
  }
}.

module FunctionalByteView = {
  proc hash = FunctionalSession.hash
  proc sign(random message shuffle : raw_input) : raw_input option = {
    var s, result; result <- None;
    if (byte_values random /\ byte_values message /\ byte_values shuffle) {
      s <@ FunctionalSession.sign(random,message,shuffle);
      if (s <> None) { result <- Some (paired_signature_bytes (oget s)); }
    }
    return result;
  }
}.

module FunctionalByteDriver (A : ByteClient) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    FunctionalSession.init(seed,root,qr,qs);
    forged <@ A(FunctionalByteView).run(seed,root);
    result <- false;
    if (!FullSession.failed /\ size forged.`1 = 32 /\ byte_values forged.`1 /\
        byte_signature forged.`2 /\ !List.mem FullSession.signed_messages forged.`1) {
      result <@ FunctionalValues.verify(seed,root,forged.`1,word_decode forged.`2);
    }
    return result;
  }
}.

lemma functional_session_hash f :
  equiv[FullSession(FixedPrefix).hash ~ FunctionalSession.hash :
    ={arg,glob FullSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f ==>
    ={res,glob FullSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc; sp 1 1; if; first by auto.
  + wp; call (functional_hash_observation f); auto.
  by auto.
qed.

lemma functional_session_sign f :
  equiv[FullSession(FixedPrefix).sign ~ FunctionalSession.sign :
    ={arg,glob FullSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,glob FullSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f /\
    (res{1} <> None => signature_width (oget res{1}))].
proof.
  proc; sp 1 1; if; first by auto.
  + wp; call (functional_signer_observation f); auto => />.
  by auto.
qed.

lemma functional_byte_view_sign f :
  equiv[ByteView(FullSession(FixedPrefix)).sign ~ FunctionalByteView.sign :
    ={arg,glob FullSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,glob FullSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc; sp 1 1; if; first by auto.
  + wp; call (functional_session_sign f); auto => />.
    move=> &m1 &m2 hf hh hr hm hsh signed history hc hs hn.
    by rewrite (signature_bytes_encoder _ (hs hn)).
  by auto.
qed.

lemma functional_byte_client f (A <: ByteClient {-FullSession,-FixedPrefix,-FixedBackend}) :
  equiv[A(ByteView(FullSession(FixedPrefix))).run ~ A(FunctionalByteView).run :
    ={arg,glob A,glob FullSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,glob A,glob FullSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc (={glob FullSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_width f /\ backend_consistent FixedBackend.history{1} f) => //.
  + by conseq (functional_session_hash f).
  by conseq (functional_byte_view_sign f); smt().
qed.

lemma functional_byte_driver f (A <: ByteClient {-FullSession,-FixedPrefix,-FixedBackend}) :
  equiv[ByteDriver(A,FixedPrefix).run ~ FunctionalByteDriver(A).run :
    ={arg,glob A,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,glob A,glob FullSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc; seq 2 2 : (={seed,root,qr,qs,forged,glob A,glob FullSession,FixedBackend.fn,FixedPrefix.key} /\
    FixedBackend.fn{1} = f /\ backend_width f /\ backend_consistent FixedBackend.history{1} f).
  + call (functional_byte_client f A); inline FullSession(FixedPrefix).init; auto.
  sp 1 1; if; first by auto.
  + call (functional_verifier_observation f); auto => />; rewrite /byte_signature /byte_values.
    move=> &m1 &m2 hf hh hfailed hm hbm hs hbs hfresh.
    split; first by apply (decode_word _ hbs).
    by apply (outer_decoded_counters _ hs).
  by auto.
qed.

lemma functional_failed_sign_refused :
  hoare[FunctionalSession.sign : FullSession.failed ==>
    res = None /\ FullSession.failed].
proof. proc; inline FunctionalValues.sign; auto. qed.

lemma functional_session_sign_lossless : islossless FunctionalSession.sign.
proof. proc; sp 1; if; auto; wp; call functional_value_sign_lossless; auto. qed.

lemma functional_session_hash_lossless : islossless FunctionalSession.hash.
proof. proc; inline FunctionalValues.hash; auto. qed.

lemma functional_byte_view_sign_lossless : islossless FunctionalByteView.sign.
proof. proc; sp 1; if; auto; wp; call functional_session_sign_lossless; auto. qed.

lemma functional_byte_driver_lossless (A <: ByteClient {-FullSession,-FixedPrefix,-FixedBackend}) :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless FunctionalByteDriver(A).run.
proof.
  move=> ha; proc; seq 2 : true 1%r 1%r 0%r 0%r => //.
  + call (ha FunctionalByteView functional_session_hash_lossless functional_byte_view_sign_lossless).
    inline FullSession(FixedPrefix).init; auto.
  sp 1; if; auto; call functional_value_verify_lossless; auto.
qed.

(* Initialized adaptive byte-session equality under the same fixed backend.
   The backend and secret are explicit inputs, not a sampled random oracle.
   No valid-history or successful-signing premise is required after init. *)




module FunctionalKeyPreparation = {
  proc run() : raw_input * raw_input * raw_input * raw_input = {
    return (KeygenInputs.random,KeygenInputs.message,
      functional_public_seed KeygenInputs.public_seed,
      functional_public_root FixedBackend.fn FixedPrefix.key KeygenInputs.public_seed);
  }
}.

module FunctionalByteContext (A : ByteClient) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ FunctionalKeyPreparation.run();
    result <@ FunctionalByteDriver(A).run(inputs.`3,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.

module FixedByteExperiment (A : ByteClient) = {
  proc run(fn : raw_input -> digest, key : raw_input) : bool = {
    var result;
    FixedBackend.init(fn); FixedPrefix.key <- key;
    result <@ ByteContext(A,FixedPrefix).run();
    return result;
  }
}.

module FunctionalByteExperiment (A : ByteClient) = {
  proc run(fn : raw_input -> digest, key : raw_input) : bool = {
    var result;
    FixedBackend.init(fn); FixedPrefix.key <- key;
    result <@ FunctionalByteContext(A).run();
    return result;
  }
}.

lemma functional_key_preparation_observation f :
  equiv[KeygenPreparation(PreparationView(FixedPrefix)).run ~ FunctionalKeyPreparation.run :
    ={glob KeygenInputs,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,glob KeygenInputs,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc*; inline{2} FunctionalKeyPreparation.run; wp.
  exists* FixedBackend.history{1}, FixedBackend.calls{1}, FixedPrefix.key{1},
    KeygenInputs.public_seed{1},KeygenInputs.random{1},KeygenInputs.message{1};
    elim* => h c key0 public0 random0 message0.
  call{1} (fixed_functional_key_preparation_total f h c key0 public0 random0 message0); auto.
qed.

lemma functional_byte_context f
  (A <: ByteClient {-FullSession,-FixedPrefix,-FixedBackend,-FullLimits,-KeygenInputs}) :
  equiv[ByteContext(A,FixedPrefix).run ~ FunctionalByteContext(A).run :
    ={glob A,glob FullLimits,glob KeygenInputs,FixedBackend.fn,FixedPrefix.key} /\
    FixedBackend.fn{1} = f /\ backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,glob A,glob FullSession,glob FullLimits,glob KeygenInputs,FixedBackend.fn,FixedPrefix.key} /\
    FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f].
proof.
  proc; call (functional_byte_driver f A); call (functional_key_preparation_observation f); auto.
qed.

lemma functional_initialized_byte_session f
  (A <: ByteClient {-FullSession,-FixedPrefix,-FixedBackend,-FullLimits,-KeygenInputs}) :
  equiv[FixedByteExperiment(A).run ~ FunctionalByteExperiment(A).run :
    ={arg,glob A,glob FullLimits,glob KeygenInputs} /\ fn{1} = f /\ backend_width f ==>
    ={res,glob A,glob FullSession,glob FullLimits,glob KeygenInputs,FixedBackend.fn,FixedPrefix.key} /\
    FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f].
proof.
  proc; call (functional_byte_context f A); inline FixedBackend.init; auto => />.
  by move=> _; apply backend_empty_consistent.
qed.

lemma functional_initialized_success_probability f key0
  (A <: ByteClient {-FullSession,-FixedPrefix,-FixedBackend,-FullLimits,-KeygenInputs}) &m :
  backend_width f =>
  Pr[FixedByteExperiment(A).run(f,key0) @ &m : res] =
  Pr[FunctionalByteExperiment(A).run(f,key0) @ &m : res].
proof.
  move=> hf; byequiv (functional_initialized_byte_session f A) => //.
qed.

lemma functional_initialized_lossless
  (A <: ByteClient {-FullSession,-FixedPrefix,-FixedBackend,-FullLimits,-KeygenInputs}) :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless FunctionalByteExperiment(A).run.
proof.
  move=> ha; proc; inline FunctionalByteContext(A).run.
  wp; call (functional_byte_driver_lossless A ha).
  inline FunctionalKeyPreparation.run FixedBackend.init; auto.
qed.
