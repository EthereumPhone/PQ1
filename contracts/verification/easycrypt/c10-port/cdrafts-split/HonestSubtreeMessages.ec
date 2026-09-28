(* Actual accepted calls establish the lower-root reference for their top message. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawForest RawSigner SignerAccepted SignerReturned FullSession SignerSubtreeReference.

op returned_subtree_reference h s seed root message (sig : raw_signature) =
  exists d, accept_digest d /\ h.[hmsg_input seed root (pad sig.`1) message]=Some d /\
    signed_subtree_reference h s seed (hypertree_index d) sig.`4.

lemma observed_signer_subtree seed0 :
  hoare [ObservedSigner(Independent).sign : seed=seed0 ==>
    res<>None => signed_subtree_reference Independent.rawhistory Independent.secrethistory
      seed0 (hypertree_index (oget SignObservation.accepted).`2) (oget res).`4].
proof.
  proc; seq 1 : (seed=seed0).
  + call (_ : true ==> true); first by trivial.
    auto.
  sp 1; if; last auto.
  exists* SignObservation.accepted; elim* => accepted0.
  call (finish_records_subtree seed0 (oget accepted0).`2); auto.
qed.

lemma observed_signer_subtree_entry seed0 root0 message0 :
  hoare [ObservedSigner(Independent).sign : seed=seed0 /\ root=root0 /\ message=message0 ==>
    res<>None => returned_subtree_reference Independent.rawhistory Independent.secrethistory
      seed0 root0 message0 (oget res)].
proof.
  conseq (observed_signer_subtree seed0) (observed_signer_entry seed0 root0 message0).
  + smt().
  move=> &m hm result h s accepted [ho he] hs.
  exists (oget accepted).`2; move: ho he; rewrite /pad; smt().
qed.

lemma raw_signer_subtree_entry seed0 root0 message0 :
  hoare [RawSigner(Independent).sign : seed=seed0 /\ root=root0 /\ message=message0 ==>
    res<>None => returned_subtree_reference Independent.rawhistory Independent.secrethistory
      seed0 root0 message0 (oget res)].
proof.
  conseq (observed_signer_refines Independent) (observed_signer_subtree_entry seed0 root0 message0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},root{m},random{m},message{m},shuffle{m}); smt().
  smt().
qed.

lemma full_sign_subtree_entry seed0 root0 message0 :
  hoare [FullSession(Independent).sign :
    FullSession.seed=seed0 /\ FullSession.root=root0 /\ message=message0 ==>
    res<>None => returned_subtree_reference Independent.rawhistory Independent.secrethistory
      seed0 root0 message0 (oget res)].
proof.
  proc; sp 1; if; last auto.
  wp; call (raw_signer_subtree_entry seed0 root0 message0); auto.
qed.
