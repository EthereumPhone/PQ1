(* Actual fresh keygen/sign, 4008-byte encoding, parsing and verification. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawKeygenCost RawSigner RawSignature ByteSession BuilderTotality.
require import MerkleRootWitness SignerFinishState SignerVerifierReplay.
require import IndependentWidths SignerEncodingCorrect.

module ActualByteSignerConstruction = {
  proc run(seed random message shuffle : raw_input) : raw_input * raw_input option * bool = {
    var root, signature, wire, verified;
    Independent.init();
    root <@ RawKeygen(PreparationView(Independent)).root(seed,1,0);
    signature <@ RawSigner(Independent).sign(seed,pad root,random,message,shuffle);
    wire <- None; verified <- false;
    if (signature<>None) {
      wire <- Some (encode_signature (oget signature));
      verified <@ RawSigner(Independent).verify(seed,pad root,message,decode_signature (oget wire));
    }
    return (root,wire,verified);
  }
}.

lemma actual_byte_signer_correct seed0 message0 :
  hoare [ActualByteSignerConstruction.run : seed=seed0 /\ message=message0 ==>
    (res.`2=None => !res.`3) /\ (res.`2<>None => byte_signature (oget res.`2) /\ res.`3)].
proof.
  proc; seq 2 : (seed=seed0 /\ message=message0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root).
  + call (keygen_root_ready seed0); call independent_init_valid; auto.
  exists* root; elim* => root0.
  seq 1 : (seed=seed0 /\ message=message0 /\ root=root0 /\
    (signature<>None =>
      byte_signature (encode_signature (oget signature)) /\
      decode_signature (encode_signature (oget signature))=oget signature /\
      exists d, accept_digest d /\
        Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad (oget signature).`1) message0]=Some d /\
        signer_finish_opening Independent.rawhistory Independent.secrethistory seed0 d (oget signature) root0)).
  + call (actual_signed_encoding seed0 root0 message0); auto; smt().
  sp 2; if; last by auto.
  conseq (_ : exists d, seed=seed0 /\ message=message0 /\ root=root0 /\ signature<>None /\
    byte_signature (encode_signature (oget signature)) /\
    decode_signature (encode_signature (oget signature))=oget signature /\ accept_digest d /\
    Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad (oget signature).`1) message0]=Some d /\
    signer_finish_opening Independent.rawhistory Independent.secrethistory seed0 d (oget signature) root0 ==> _).
  + smt().
  elim* => d; exists* signature; elim* => sig0.
  call (raw_verify_opening seed0 root0 message0 (oget sig0) d); auto; smt().
qed.

lemma actual_byte_signer_lossless : islossless ActualByteSignerConstruction.run.
proof.
  proc; seq 3 : true 1%r 1%r 0%r 0%r => //.
  + call (signer_sign_lossless Independent independent_hash_ll independent_derive_ll).
    call (root_lossless (PreparationView(Independent)) independent_hash_ll preparation_wots_ll).
    inline Independent.init; auto.
  sp 2; if; auto.
  call (signer_verify_lossless Independent independent_hash_ll); auto.
qed.

lemma total_actual_byte_signer_correct seed0 message0 :
  phoare [ActualByteSignerConstruction.run : seed=seed0 /\ message=message0 ==>
    (res.`2=None => !res.`3) /\ (res.`2<>None => byte_signature (oget res.`2) /\ res.`3)] = 1%r.
proof. conseq actual_byte_signer_lossless (actual_byte_signer_correct seed0 message0); smt(). qed.
