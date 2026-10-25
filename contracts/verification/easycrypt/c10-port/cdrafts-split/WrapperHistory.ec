(* The wrapper retains the first signature's evidence through its second
   signing pass and internal verification, including every refusal branch. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawSigner RawWrapper WrapperSession.
require import PersistentGrind AcceptedContexts MonotoneHistory SignerTrace VerifierHistory.
require import ForestReferenceHistory RootSessionHistory MerkleRootWitness.
require import ExposureLog ExposureSupport MinimumExposureSupport.
require import HonestForestMessages HonestSubtreeMessages HonestMinimumCounts.

lemma wrapper_verifier_histories (V <: PublicVerifier {-Independent}) s0 h0 :
  hoare [V(Independent).verify :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  exact (independent_hash_extends s0 h0).
qed.

lemma raw_wrapper_histories s0 h0 :
  hoare [RawWrapper(Independent).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; sp 1; if; last auto.
  seq 1 : (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + call (complete_signer_histories RawSigner s0 h0); auto.
  if; last auto.
  seq 1 : (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + call (complete_signer_histories RawSigner s0 h0); auto.
  if; last auto.
  wp; call (wrapper_verifier_histories RawSigner s0 h0); auto.
qed.

lemma wrapper_hash_histories s0 h0 :
  hoare [WrapperSession(Independent).hash :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. proc; sp 1; if; auto; wp; call (independent_hash_extends s0 h0); auto. qed.

lemma wrapper_sign_histories s0 h0 :
  hoare [WrapperSession(Independent).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. proc; sp 1; if; auto; wp; call (raw_wrapper_histories s0 h0); auto. qed.

op wrapper_entry_supported h s seed root (entry : signing_exposure) =
  exposure_supported h s seed root entry /\ minimum_entry h s seed root entry.

lemma wrapper_entry_extends h h' s s' seed root entry :
  extends h h' => extends s s' => wrapper_entry_supported h s seed root entry =>
  wrapper_entry_supported h' s' seed root entry.
proof.
  rewrite /wrapper_entry_supported /exposure_supported /minimum_entry.
  smt(returned_forest_extends returned_subtree_extends returned_minimum_extends).
qed.

lemma wrapper_signer_entry_preserved (S <: CompleteSigner {-Independent}) seed0 root0 entry0 :
  hoare [S(Independent).sign :
    wrapper_entry_supported Independent.rawhistory Independent.secrethistory seed0 root0 entry0 ==>
    wrapper_entry_supported Independent.rawhistory Independent.secrethistory seed0 root0 entry0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (complete_signer_histories S s0 h0); smt(extends_refl wrapper_entry_extends).
qed.

lemma wrapper_verifier_entry_preserved (V <: PublicVerifier {-Independent}) seed0 root0 entry0 :
  hoare [V(Independent).verify :
    wrapper_entry_supported Independent.rawhistory Independent.secrethistory seed0 root0 entry0 ==>
    wrapper_entry_supported Independent.rawhistory Independent.secrethistory seed0 root0 entry0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (wrapper_verifier_histories V s0 h0); smt(extends_refl wrapper_entry_extends).
qed.

lemma wrapper_raw_signer_entry seed0 root0 message0 :
  hoare [RawSigner(Independent).sign : seed=seed0 /\ root=root0 /\ message=message0 ==>
    res<>None => wrapper_entry_supported Independent.rawhistory Independent.secrethistory
      seed0 root0 (message0,oget res)].
proof.
  have he : hoare [RawSigner(Independent).sign : seed=seed0 /\ root=root0 /\ message=message0 ==>
    res<>None => exposure_supported Independent.rawhistory Independent.secrethistory
      seed0 root0 (message0,oget res)]
    by conseq (raw_signer_forest_entry seed0 root0 message0)
      (raw_signer_subtree_entry seed0 root0 message0); rewrite /exposure_supported; smt().
  conseq he (raw_signer_minimum_entry seed0 root0 message0);
    rewrite /wrapper_entry_supported /minimum_entry; smt().
qed.

lemma raw_wrapper_supported seed0 root0 message0 :
  hoare [RawWrapper(Independent).sign : seed=seed0 /\ root=root0 /\ message=message0 ==>
    res<>None => wrapper_entry_supported Independent.rawhistory Independent.secrethistory
      seed0 root0 (message0,oget res)].
proof.
  proc; sp 1; if; last auto.
  seq 1 : (result=None /\
    (first<>None => wrapper_entry_supported Independent.rawhistory Independent.secrethistory
      seed0 root0 (message0,oget first))).
  + call (wrapper_raw_signer_entry seed0 root0 message0); auto.
  if; last auto.
  exists* first; elim* => first0.
  seq 1 : (first=first0 /\ result=None /\
    wrapper_entry_supported Independent.rawhistory Independent.secrethistory
      seed0 root0 (message0,oget first0)).
  + call (wrapper_signer_entry_preserved RawSigner seed0 root0 (message0,oget first0)); auto.
  if; last auto.
  wp; call (wrapper_verifier_entry_preserved RawSigner seed0 root0 (message0,oget first0)); auto.
qed.

lemma wrapper_sign_supported_history seed0 root0 message0 s0 h0 :
  hoare [WrapperSession(Independent).sign :
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\ message=message0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (res<>None => wrapper_entry_supported Independent.rawhistory Independent.secrethistory
      seed0 root0 (message0,oget res))].
proof.
  have he : hoare [WrapperSession(Independent).sign :
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\ message=message0 ==>
    res<>None => wrapper_entry_supported Independent.rawhistory Independent.secrethistory
      seed0 root0 (message0,oget res)].
  + proc; sp 1; if; last auto.
    wp; call (raw_wrapper_supported seed0 root0 message0); auto.
  conseq (wrapper_sign_histories s0 h0) he; smt().
qed.

lemma wrapper_hash_root_preserved seed0 layer0 tree0 root0 :
  hoare [WrapperSession(Independent).hash :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (wrapper_hash_histories s0 h0); smt(extends_refl merkle_root_witness_extends).
qed.

lemma wrapper_sign_root_preserved seed0 layer0 tree0 root0 :
  hoare [WrapperSession(Independent).sign :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (wrapper_sign_histories s0 h0); smt(extends_refl merkle_root_witness_extends).
qed.
