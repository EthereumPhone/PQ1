(* Later permitted adaptive calls retain each complete forest reference. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawSigner FullSession.
require import PersistentGrind AcceptedContexts MonotoneHistory SignerTrace VerifierHistory.
require import ForestRootWitness.

lemma complete_signer_histories (S <: CompleteSigner {-Independent}) s0 h0 :
  hoare [S(Independent).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  exact (independent_derive_extends s0 h0).
qed.

lemma full_hash_histories s0 h0 :
  hoare [FullSession(Independent).hash :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. proc; sp 1; if; auto; wp; call (independent_hash_extends s0 h0); auto. qed.

lemma full_sign_histories s0 h0 :
  hoare [FullSession(Independent).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. proc; sp 1; if; auto; wp; call (complete_signer_histories RawSigner s0 h0); auto. qed.

lemma full_client_histories (A <: FullClient {-FullSession,-Independent}) s0 h0 :
  hoare [A(FullSession(Independent)).run :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (full_hash_histories s0 h0).
  exact (full_sign_histories s0 h0).
qed.

lemma full_client_forest_preserved (A <: FullClient {-FullSession,-Independent}) seed0 ht0 root0 :
  hoare [A(FullSession(Independent)).run :
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 root0 ==>
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 root0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (full_client_histories A s0 h0); smt(extends_refl forest_root_witness_extends).
qed.

lemma public_verifier_forest_preserved (V <: PublicVerifier {-Independent}) seed0 ht0 root0 :
  hoare [V(Independent).verify :
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 root0 ==>
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 root0].
proof.
  proc (forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 root0) => //.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (independent_hash_extends s0 h0); smt(extends_refl forest_root_witness_extends).
qed.
