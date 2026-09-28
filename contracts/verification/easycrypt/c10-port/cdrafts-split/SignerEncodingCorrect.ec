(* Actual signed values satisfy both the retained opening and exact codec. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner RawSignature ByteSession.
require import MerkleRootWitness RawMerkleRootWitness SignerFinishState SignerReturnedOpening.
require import IndependentWidths IndependentSignerWidth RawByteValues RawSignerBytes EncodedSignature.

lemma keygen_root_ready seed0 :
  hoare [RawKeygen(PreparationView(Independent)).root :
    seed=seed0 /\ layer=1 /\ tree=0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 res].
proof.
  conseq (keygen_root_recorded seed0 1 0) (width_keygen_valid RawKeygen); smt().
qed.
lemma independent_signature_wire :
  hoare [RawSigner(Independent).sign :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    res<>None => signature_width (oget res) /\ signature_bytes (oget res)].
proof.
  conseq independent_signer_width (raw_signer_bytes Independent independent_hash_ll independent_derive_ll); smt().
qed.
lemma actual_signed_encoding seed0 root0 message0 :
  hoare [RawSigner(Independent).sign :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    res<>None =>
    byte_signature (encode_signature (oget res)) /\ decode_signature (encode_signature (oget res))=oget res /\
    exists d, accept_digest d /\
      Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad (oget res).`1) message0]=Some d /\
      signer_finish_opening Independent.rawhistory Independent.secrethistory seed0 d (oget res) root0].
proof.
  conseq (raw_signer_complete_opening seed0 root0 message0) independent_signature_wire;
    rewrite /byte_signature; smt(encoded_signature_width encoded_signature_bytes signature_encoding_roundtrip).
qed.
