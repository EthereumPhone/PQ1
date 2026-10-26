(* Actual public/private oracle calls retain exact append-only key provenance.
   Abstract interfaces prevent the caller from changing the memo histories. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PersistentGrind AcceptedContexts MonotoneHistory.
require import RawSigner SignerTrace VerifierHistory.
require import AddressedQueryProvenance.

lemma complete_signer_appended_queries (S <: CompleteSigner {-Independent}) old base :
  hoare [S(Independent).sign : appended_query_history old base Independent.rawhistory Independent.queries ==>
    appended_query_history old base Independent.rawhistory Independent.queries].
proof.
  proc (appended_query_history old base Independent.rawhistory Independent.queries) => //.
  + exact (hash_appended_query_history old base).
  exact (derive_appended_query_history old base).
qed.

lemma public_verifier_appended_queries (V <: PublicVerifier {-Independent}) old base :
  hoare [V(Independent).verify : appended_query_history old base Independent.rawhistory Independent.queries ==>
    appended_query_history old base Independent.rawhistory Independent.queries].
proof.
  proc (appended_query_history old base Independent.rawhistory Independent.queries) => //.
  exact (hash_appended_query_history old base).
qed.

lemma public_verifier_extends_histories (V <: PublicVerifier {-Independent}) h0 s0 :
  hoare [V(Independent).verify : extends h0 Independent.rawhistory /\ extends s0 Independent.secrethistory ==>
    extends h0 Independent.rawhistory /\ extends s0 Independent.secrethistory].
proof.
  proc (extends h0 Independent.rawhistory /\ extends s0 Independent.secrethistory) => //.
  conseq (independent_hash_extends s0 h0); smt().
qed.
