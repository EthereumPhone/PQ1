(* Byte-facing view of the existing adaptive wrapper. The view checks byte
   values; the underlying session retains width/cap admission, charged
   refusals, retries and the ledger of externally released messages. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion PreparedGrind.
require import RawSigner RawSignature RawDecode ByteSession.
require import WrapperSession WrapperLossless.

module type WrapperByteClientOracle = {
  proc hash(x : raw_input) : digest
  proc sign(random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_input option
}.
module type WrapperByteClient (O : WrapperByteClientOracle) = {
  proc run(seed root : raw_input) : raw_input * raw_input { O.hash, O.sign }
}.
module WrapperByteView (O : WrapperClientOracle) = {
  proc hash = O.hash
  proc sign(random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_input option = {
    var signature, result; result <- None;
    if (byte_values random /\ byte_values message /\
        byte_values shuffle_a /\ byte_values shuffle_b) {
      signature <@ O.sign(random,message,shuffle_a,shuffle_b,ready,final_guard);
      if (signature <> None) { result <- Some (encode_signature (oget signature)); }
    }
    return result;
  }
}.
module WrapperByteLift (A : WrapperByteClient) (O : WrapperClientOracle) = {
  proc run(seed root : raw_input) : raw_input * raw_signature = {
    var forged, message;
    forged <@ A(WrapperByteView(O)).run(seed,root);
    message <- [];
    if (byte_signature forged.`2 /\ byte_values forged.`1) { message <- forged.`1; }
    return (message,decode_signature forged.`2);
  }
}.
module WrapperByteDriver (A : WrapperByteClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    WrapperSession(O).init(seed,root,qr,qs);
    forged <@ A(WrapperByteView(WrapperSession(O))).run(seed,root);
    result <- false;
    if (size forged.`1 = 32 /\ byte_values forged.`1 /\ byte_signature forged.`2 /\
        !List.mem WrapperSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,decode_signature forged.`2);
    }
    return result;
  }
}.
module WrapperByteContext (A : WrapperByteClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ WrapperByteDriver(A,O).run(inputs.`3,inputs.`4,
      WrapperLimits.raw_cap,WrapperLimits.sign_cap);
    return result;
  }
}.

lemma wrapper_byte_view_sign_lossless (O <: WrapperClientOracle) :
  islossless O.sign => islossless WrapperByteView(O).sign.
proof. move=> hs; proc; sp 1; if; auto; wp; call hs; auto. qed.

lemma wrapper_byte_lift_lossless (A <: WrapperByteClient)
    (O <: WrapperClientOracle {-A}) :
  (forall (V <: WrapperByteClientOracle {-A}),
    islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.sign => islossless WrapperByteLift(A,O).run.
proof.
  move=> ha hh hs; proc; wp;
    call (ha (WrapperByteView(O)) hh (wrapper_byte_view_sign_lossless O hs)); auto.
qed.

lemma wrapper_byte_driver_equiv
    (A <: WrapperByteClient {-WrapperSession})
    (O <: PrefixOracle {-A,-WrapperSession}) :
  equiv[WrapperByteDriver(A,O).run ~ WrapperDriver(WrapperByteLift(A),O).run :
    ={arg,glob A,glob O} ==> ={res,glob A,glob O,glob WrapperSession}].
proof.
  proc; inline WrapperSession(O).init WrapperByteLift(A,WrapperSession(O)).run.
  seq 12 14 : (={seed,root,qr,qs,glob A,glob O,glob WrapperSession} /\ forged{1}=forged0{2}).
  + call (_ : ={glob WrapperSession,glob O}); 1,2: by sim.
    auto.
  sp 1 4; if.
  + auto; rewrite /byte_signature; smt(decoded_signature_width).
  + call (_ : ={glob O}); first by sim.
    auto; smt().
  auto; smt().
qed.

lemma wrapper_byte_context_equiv
    (A <: WrapperByteClient {-WrapperSession})
    (O <: PrefixOracle {-A,-WrapperSession,-WrapperLimits,-KeygenInputs}) :
  equiv[WrapperByteContext(A,O).run ~ WrapperContext(WrapperByteLift(A),O).run :
    ={glob A,glob O,glob WrapperLimits,glob KeygenInputs} ==>
    ={res,glob A,glob O,glob WrapperSession}].
proof.
  proc; call (wrapper_byte_driver_equiv A O).
  call (_ : ={glob O,glob KeygenInputs}); first by sim.
  auto.
qed.

lemma wrapper_byte_driver_lossless
    (A <: WrapperByteClient {-WrapperSession})
    (O <: PrefixOracle {-A,-WrapperSession}) :
  (forall (V <: WrapperByteClientOracle {-A}),
    islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless WrapperByteDriver(A,O).run.
proof.
  move=> ha hh hd; proc; seq 2 : true 1%r 1%r 0%r 0%r => //.
  + call (ha (WrapperByteView(WrapperSession(O))) (wrapper_hash_lossless O hh)
      (wrapper_byte_view_sign_lossless (WrapperSession(O)) (wrapper_sign_lossless O hh hd)));
      inline WrapperSession(O).init; auto.
  sp 1; if; auto; call (signer_verify_lossless O hh); auto.
qed.

lemma wrapper_byte_context_lossless
    (A <: WrapperByteClient {-WrapperSession})
    (O <: PrefixOracle {-A,-WrapperSession}) :
  (forall (V <: WrapperByteClientOracle {-A}),
    islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless WrapperByteContext(A,O).run.
proof.
  move=> ha hh hd; have [#] hvh hvw hvf := preparation_view_lossless O hh hd.
  proc; call (wrapper_byte_driver_lossless A O ha hh hd).
  call (keygen_preparation_lossless (PreparationView(O)) hvh hvw hvf); auto.
qed.
