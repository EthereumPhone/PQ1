(* Success of the original adaptive session yields the linked subtree cases. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner RawSignature FullSession.
require import MerkleRootWitness RootSessionHistory VerifierLayerRecords SubtreeOpeningCases.
require import MemoNodeCollision PublicNodeZero.

op new_message_subtree_opening h s seed root messages =
  merkle_root_witness h s seed 1 0 root /\
  exists message sig, size message=32 /\ signature_width sig /\ !List.mem messages message /\
    verified_subtree_opening h s seed root message sig.

lemma verifier_extracts_subtree seed0 root0 message0 (sig0 : raw_signature) :
  hoare [RawSigner(Independent).verify :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ signature_width sig0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 /\
    (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      verified_subtree_opening Independent.rawhistory Independent.secrethistory seed0 root0 message0 sig0)].
proof.
  conseq (verifier_records_layers seed0 root0 message0 sig0)
    (public_verifier_root_preserved RawSigner seed0 1 0 root0); smt(verified_records_to_subtree).
qed.

lemma full_driver_subtree_extraction (A <: FullClient {-FullSession,-Independent}) seed0 root0 :
  hoare [FullDriver(A,Independent).run :
    seed=seed0 /\ root=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      new_message_subtree_opening Independent.rawhistory Independent.secrethistory seed0 root0 FullSession.signed_messages].
proof.
  proc; seq 2 : (seed=seed0 /\ root=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0).
  + call (full_client_root_preserved A seed0 1 0 root0); inline FullSession(Independent).init; auto.
  sp 1; if; last auto.
  exists* forged; elim* => f0.
  call (verifier_extracts_subtree seed0 root0 f0.`1 f0.`2).
  auto; rewrite /new_message_subtree_opening; smt().
qed.
