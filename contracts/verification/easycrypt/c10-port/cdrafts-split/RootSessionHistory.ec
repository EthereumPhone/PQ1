(* Adaptive signing and public calls preserve the original complete root. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawSigner.
require import PersistentGrind AcceptedContexts MonotoneHistory MerkleRootWitness.
require import SignerTrace VerifierHistory FullSession.

lemma root_hash_preserved seed0 layer0 tree0 root0 :
  hoare [Independent.hash :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (independent_hash_extends s0 h0); smt(extends_refl merkle_root_witness_extends).
qed.

lemma root_derive_preserved seed0 layer0 tree0 root0 :
  hoare [Independent.derive :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (independent_derive_extends s0 h0); smt(extends_refl merkle_root_witness_extends).
qed.

lemma complete_signer_root_preserved (S <: CompleteSigner {-Independent}) seed0 layer0 tree0 root0 :
  hoare [S(Independent).sign :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  proc (merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0) => //.
  + exact (root_hash_preserved seed0 layer0 tree0 root0).
  exact (root_derive_preserved seed0 layer0 tree0 root0).
qed.

lemma full_hash_root_preserved seed0 layer0 tree0 root0 :
  hoare [FullSession(Independent).hash :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  proc; sp 1; if; auto; wp; call (root_hash_preserved seed0 layer0 tree0 root0); auto.
qed.

lemma full_sign_root_preserved seed0 layer0 tree0 root0 :
  hoare [FullSession(Independent).sign :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  proc; sp 1; if; auto; wp; call (complete_signer_root_preserved RawSigner seed0 layer0 tree0 root0); auto.
qed.

lemma full_client_root_preserved (A <: FullClient {-FullSession,-Independent}) seed0 layer0 tree0 root0 :
  hoare [A(FullSession(Independent)).run :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  proc (merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0) => //.
  + exact (full_hash_root_preserved seed0 layer0 tree0 root0).
  exact (full_sign_root_preserved seed0 layer0 tree0 root0).
qed.

lemma public_verifier_root_preserved (V <: PublicVerifier {-Independent}) seed0 layer0 tree0 root0 :
  hoare [V(Independent).verify :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  proc (merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0) => //.
  exact (root_hash_preserved seed0 layer0 tree0 root0).
qed.
