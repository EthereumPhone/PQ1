(* The accepted H_msg digest and retained component trace belong to one signature. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess RawKeygen RoleGrind RawSigner.
require import SignerAccepted SignerReturned MerkleRootWitness SignerGrindRoot SignerFinishState SignerFinishRecorded.

lemma observed_signer_opening seed0 root0 :
  hoare [ObservedSigner(Independent).sign :
    seed=seed0 /\ merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    res<>None => signer_finish_opening Independent.rawhistory Independent.secrethistory
      seed0 (oget SignObservation.accepted).`2 (oget res) root0].
proof.
  proc; seq 1 : (seed=seed0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0).
  + call (grind_keeps_top_root seed0 root0); auto.
  sp 1; if; last by auto.
  exists* SignObservation.accepted; elim* => accepted0.
  call (raw_finish_recorded seed0 (oget accepted0).`2 root0); auto; smt().
qed.

lemma observed_signer_complete_opening seed0 root0 message0 :
  hoare [ObservedSigner(Independent).sign :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    res<>None => exists d,
      accept_digest d /\ Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad (oget res).`1) message0]=Some d /\
      signer_finish_opening Independent.rawhistory Independent.secrethistory seed0 d (oget res) root0].
proof.
  conseq (observed_signer_opening seed0 root0) (observed_signer_entry seed0 (pad root0) message0).
  + smt().
  move=> &m hm result h s accepted [ho he] hs; exists (oget accepted).`2.
  move: he ho; rewrite /pad; smt().
qed.

lemma raw_signer_complete_opening seed0 root0 message0 :
  hoare [RawSigner(Independent).sign :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    res<>None => exists d,
      accept_digest d /\ Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad (oget res).`1) message0]=Some d /\
      signer_finish_opening Independent.rawhistory Independent.secrethistory seed0 d (oget res) root0].
proof.
  conseq (observed_signer_refines Independent) (observed_signer_complete_opening seed0 root0 message0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},root{m},random{m},message{m},shuffle{m}); smt().
  smt().
qed.
