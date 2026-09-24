(* A same-client honest-correctness event for either oracle interface. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes.
require import RawKeygen RawKeygenCost RawSigner RawSignature ByteSession PreparedGrind.
require import ActualByteSignerCorrect.

module HonestByteInputs = {
  var seed, random, message, shuffle : raw_input
}.
module HonestByteError (O : PrefixOracle) = {
  proc run() : bool = {
    var root, signature, wire, verified;
    root <@ RawKeygen(PreparationView(O)).root(HonestByteInputs.seed,1,0);
    signature <@ RawSigner(O).sign(HonestByteInputs.seed,pad root,
      HonestByteInputs.random,HonestByteInputs.message,HonestByteInputs.shuffle);
    wire <- None; verified <- false;
    if (signature<>None) {
      wire <- Some (encode_signature (oget signature));
      verified <@ RawSigner(O).verify(HonestByteInputs.seed,pad root,HonestByteInputs.message,
        decode_signature (oget wire));
    }
    return wire<>None /\ (!byte_signature (oget wire) \/ !verified);
  }
}.
module CheckedByteError = {
  proc run() : bool = {
    var result;
    result <@ ActualByteSignerConstruction.run(HonestByteInputs.seed,HonestByteInputs.random,
      HonestByteInputs.message,HonestByteInputs.shuffle);
    return result.`2<>None /\ (!byte_signature (oget result.`2) \/ !result.`3);
  }
}.

lemma independent_honest_byte_refinement :
  equiv [IndependentGame(HonestByteError).run ~ CheckedByteError.run :
    ={glob HonestByteInputs} ==> ={res}].
proof.
  proc; inline HonestByteError(Independent).run ActualByteSignerConstruction.run.
  seq 3 7 : (={signature,root,glob Independent,glob HonestByteInputs} /\
    seed{2}=HonestByteInputs.seed{1} /\ random{2}=HonestByteInputs.random{1} /\
    message{2}=HonestByteInputs.message{1} /\ shuffle{2}=HonestByteInputs.shuffle{1}).
  + call (_ : ={arg,glob Independent} ==> ={res,glob Independent}); first by sim.
    call (_ : ={arg,glob Independent} ==> ={res,glob Independent}); first by sim.
    inline Independent.init; auto.
  wp; sp 2 2; if; auto.
  call (_ : ={arg,glob Independent} ==> ={res,glob Independent}); first by sim.
  auto.
qed.

lemma checked_byte_error_zero &m : Pr[CheckedByteError.run() @ &m : res]=0%r.
proof.
  byphoare (_ : true ==> res) => //; hoare; proc.
  exists* HonestByteInputs.seed,HonestByteInputs.message; elim* => seed0 message0.
  call (actual_byte_signer_correct seed0 message0); auto; smt().
qed.

lemma independent_honest_byte_error_zero &m :
  Pr[IndependentGame(HonestByteError).run() @ &m : res]=0%r.
proof.
  have he : Pr[IndependentGame(HonestByteError).run() @ &m : res]=Pr[CheckedByteError.run() @ &m : res]
    by byequiv independent_honest_byte_refinement => //.
  rewrite he; exact (checked_byte_error_zero &m).
qed.

lemma honest_byte_context_lossless (O <: PrefixOracle {-HonestByteInputs}) :
  islossless O.hash => islossless O.derive => islossless HonestByteError(O).run.
proof.
  move=> hh hd; have [#] hvh hvw hvf := preparation_view_lossless O hh hd.
  proc; seq 2 : true 1%r 1%r 0%r 0%r => //.
  + call (signer_sign_lossless O hh hd); call (root_lossless (PreparationView(O)) hvh hvw); auto.
  sp 2; if; auto; call (signer_verify_lossless O hh); auto.
qed.
