require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner.
require import MerkleRootWitness SignerCoordinates SignerFinishState SignerFinishWitness SignerReturnedOpening SignerVerifierReplay ActualSignerCorrect.
lemma raw_verify_opening seed0 root0 message0 (sig0 : raw_signature) digest0 :
  hoare [RawSigner(Independent).verify :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\
    Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some digest0 /\
    signer_finish_opening Independent.rawhistory Independent.secrethistory seed0 digest0 sig0 root0 ==> res].
proof. exact (raw_verify_opening seed0 root0 message0 sig0 digest0). qed.
