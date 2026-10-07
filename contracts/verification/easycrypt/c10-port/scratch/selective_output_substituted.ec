(* The reference returns the exact client pair passed to the original verifier.
   Its result is related to the private observer, including rejected outputs. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawSigner RawSignature FullSession ExposureLog ClientQueryLog ClientQueryDriver.

require import ClientOutputBinding.
module SubstitutedOutputDriver (A : FullClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    FullSession(O).init(seed,root,qr,qs);
    ExposureLog.entries <- [];
    ClientQueryLog.inputs <- [];
    ClientQueryLog.output <- ([],([],[],[],[]));
    forged <@ A(QueryExposureSession(O)).run(seed,root);
    ClientQueryLog.output <- ([],([],[],[],[]));
    result <- false;
    if (!FullSession.failed /\ size forged.`1=32 /\ signature_width forged.`2 /\
        !List.mem FullSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.
lemma client_query_output_binding
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  equiv [SubstitutedOutputDriver(A,O).run ~ ClientOutputDriver(A,O).run :
    ={arg,glob A,glob O} ==>
    res{1}=res{2}.`1 /\ ClientQueryLog.output{1}=res{2}.`2 /\
    ={glob A,glob O,glob FullSession,glob ExposureLog,ClientQueryLog.inputs}].
proof.
  proc; seq 6 4 : (={seed,root,forged,glob A,glob O,glob FullSession,glob ExposureLog,ClientQueryLog.inputs} /\
    ClientQueryLog.output{1}=forged{1}).
  + wp; call (_ : ={glob O,glob FullSession,glob ExposureLog,ClientQueryLog.inputs}); 1,2: by sim.
    wp; inline FullSession(O).init; by auto.
  sp 1 1; if; auto; call (_ : ={glob O}); first by sim.
  auto.
qed.

