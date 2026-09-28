require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner.
require import MerkleRootWitness SignerCoordinates SignerFinishState SignerFinishWitness SignerReturnedOpening SignerVerifierReplay ActualSignerCorrect.
lemma raw_signer_complete_opening seed0 root0 message0 :
  hoare [RawSigner(Independent).sign :
    seed=seed0 /\ root=pad root0 /\ message=message0 ==>
    res<>None => exists d,
      accept_digest d /\ Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad (oget res).`1) message0]=Some d /\
      signer_finish_opening Independent.rawhistory Independent.secrethistory seed0 d (oget res) root0].
proof. exact (raw_signer_complete_opening seed0 root0 message0). qed.
