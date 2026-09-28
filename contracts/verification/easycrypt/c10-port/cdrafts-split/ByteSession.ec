(* Byte-facing EUF experiment and explicit adapter to the structured game.
   Raw hash queries are left unrestricted, which grants at least byte queries. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawSigner RawSignature RawDecode FullSession.

op byte_values (bs : raw_input) = all (fun b => 0 <= b < 256) bs.
op byte_signature (bs : raw_input) = size bs = 4008 /\ byte_values bs.
module type ByteClientOracle = {
  proc hash(x : raw_input) : digest
  proc sign(random message shuffle : raw_input) : raw_input option
}.
module type ByteClient (O : ByteClientOracle) = {
  proc run(seed root : raw_input) : raw_input * raw_input { O.hash, O.sign }
}.
module ByteView (O : FullClientOracle) = {
  proc hash = O.hash
  proc sign(random message shuffle : raw_input) : raw_input option = {
    var s, result; result <- None;
    if (byte_values random /\ byte_values message /\ byte_values shuffle) {
      s <@ O.sign(random,message,shuffle);
      if (s <> None) { result <- Some (encode_signature (oget s)); }
    }
    return result;
  }
}.
module ByteLift (A : ByteClient) (O : FullClientOracle) = {
  proc run(seed root : raw_input) : raw_input * raw_signature = {
    var forged, message;
    forged <@ A(ByteView(O)).run(seed,root);
    message <- [];
    if (byte_signature forged.`2 /\ byte_values forged.`1) { message <- forged.`1; }
    return (message,decode_signature forged.`2);
  }
}.
module ByteDriver (A : ByteClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    FullSession(O).init(seed,root,qr,qs);
    forged <@ A(ByteView(FullSession(O))).run(seed,root);
    result <- false;
    if (!FullSession.failed /\ size forged.`1 = 32 /\ byte_values forged.`1 /\ byte_signature forged.`2 /\
        !List.mem FullSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,decode_signature forged.`2);
    }
    return result;
  }
}.
module ByteContext (A : ByteClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ ByteDriver(A,O).run(inputs.`3,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.
lemma byte_view_sign_lossless (O <: FullClientOracle) :
  islossless O.sign => islossless ByteView(O).sign.
proof. move=> hs; proc; sp 1; if; auto; wp; call hs; auto. qed.
lemma byte_lift_lossless (A <: ByteClient) (O <: FullClientOracle {-A}) :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.sign => islossless ByteLift(A,O).run.
proof.
  move=> ha hh hs; proc; wp; call (ha (ByteView(O)) hh (byte_view_sign_lossless O hs)); auto.
qed.
lemma byte_driver_equiv (A <: ByteClient {-FullSession}) (O <: PrefixOracle {-A,-FullSession}) :
  equiv[ByteDriver(A,O).run ~ FullDriver(ByteLift(A),O).run :
    ={arg,glob A,glob O} ==> ={res,glob A,glob O,glob FullSession}].
proof.
  proc; inline FullSession(O).init ByteLift(A,FullSession(O)).run.
  seq 13 15 : (={seed,root,qr,qs,glob A,glob O,glob FullSession} /\ forged{1} = forged0{2}).
  + call (_ : ={glob FullSession,glob O}); 1,2: by sim.
    auto.
  sp 1 4; if.
  + auto; rewrite /byte_signature; smt(decoded_signature_width).
  + call (_ : ={glob O}); first by sim.
    auto; smt().
  auto; smt().
qed.
lemma byte_context_equiv
  (A <: ByteClient {-FullSession}) (O <: PrefixOracle {-A,-FullSession,-FullLimits,-KeygenInputs}) :
  equiv[ByteContext(A,O).run ~ FullContext(ByteLift(A),O).run :
    ={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob O,glob FullSession}].
proof.
  proc; call (byte_driver_equiv A O).
  call (_ : ={glob O,glob KeygenInputs}); first by sim.
  auto.
qed.
