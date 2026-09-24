(* Total honest correctness of actual keygen/sign/verify over one memoized oracle.
   Grinding or WOTS count failure stays explicit in the optional signature. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawKeygenCost RawSigner RawMerkleRootWitness MerkleRootWitness BuilderTotality.
require import SignerFinishState SignerReturnedOpening SignerVerifierReplay.

module ActualSignerConstruction (O : PrefixOracle) = {
  proc run(seed random message shuffle : raw_input) : raw_input * raw_signature option * bool = {
    var root, signature, verified;
    root <@ RawKeygen(PreparationView(O)).root(seed,1,0);
    signature <@ RawSigner(O).sign(seed,pad root,random,message,shuffle);
    verified <- false;
    if (signature<>None) {
      verified <@ RawSigner(O).verify(seed,pad root,message,oget signature);
    }
    return (root,signature,verified);
  }
}.

lemma actual_signer_correct seed0 message0 :
  hoare [ActualSignerConstruction(Independent).run : seed=seed0 /\ message=message0 ==>
    (res.`2=None => !res.`3) /\ (res.`2<>None => res.`3)].
proof.
  proc; seq 1 : (seed=seed0 /\ message=message0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root).
  + call (keygen_root_recorded seed0 1 0); auto.
  exists* root; elim* => root0.
  seq 1 : (seed=seed0 /\ message=message0 /\ root=root0 /\
    (signature<>None => exists d, accept_digest d /\
      Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad (oget signature).`1) message0]=Some d /\
      signer_finish_opening Independent.rawhistory Independent.secrethistory seed0 d (oget signature) root0)).
  + call (raw_signer_complete_opening seed0 root0 message0); auto; smt().
  sp 1; if; last by auto.
  conseq (_ : exists d, seed=seed0 /\ message=message0 /\ root=root0 /\ signature<>None /\ accept_digest d /\
    Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad (oget signature).`1) message0]=Some d /\
    signer_finish_opening Independent.rawhistory Independent.secrethistory seed0 d (oget signature) root0 ==> _).
  + smt().
  elim* => d; exists* signature; elim* => sig0.
  call (raw_verify_opening seed0 root0 message0 (oget sig0) d); auto; smt().
qed.

lemma actual_signer_lossless : islossless ActualSignerConstruction(Independent).run.
proof.
  proc; seq 2 : true 1%r 1%r 0%r 0%r => //.
  + call (signer_sign_lossless Independent independent_hash_ll independent_derive_ll).
    call (root_lossless (PreparationView(Independent)) independent_hash_ll preparation_wots_ll); auto.
  sp 1; if; auto.
  call (signer_verify_lossless Independent independent_hash_ll); auto.
qed.

lemma total_actual_signer_correct seed0 message0 :
  phoare [ActualSignerConstruction(Independent).run : seed=seed0 /\ message=message0 ==>
    (res.`2=None => !res.`3) /\ (res.`2<>None => res.`3)] = 1%r.
proof. conseq actual_signer_lossless (actual_signer_correct seed0 message0); smt(). qed.
