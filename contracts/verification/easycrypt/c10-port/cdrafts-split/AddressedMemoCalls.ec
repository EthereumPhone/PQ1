(* Distinct nonordinary-key charges for actual calls. Cached calls are not
   counted twice, and private-table extension can only improve classification. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PersistentGrind AcceptedContexts.
require import RawSigner RawSignerCost SignerTrace ForestReferenceHistory IndependentWidths.
require import AddressedOrdinaryInputs AddressedOrdinarySigner AddressedQueryProvenance.
require import AddressedSignerProvenance AddressedMemoCount.
require import AddressedForsExceptionCount AddressedSignerExceptionCount.

lemma nonordinary_hash_count seed0 q :
  hoare [Independent.hash : nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q ==>
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q+1].
proof. proc; sp 1; if; auto; smt(nonordinary_count_insert). qed.

lemma nonordinary_hash_valid_count seed0 q :
  hoare [Independent.hash : nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q+1 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof. conseq (nonordinary_hash_count seed0 q) independent_hash_width; smt(). qed.

lemma nonordinary_derive_count seed0 q :
  hoare [Independent.derive : nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q ==>
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q].
proof. proc; if; auto; smt(nonordinary_count_private_extends extends_insert). qed.

lemma signer_histories_appended h0 s0 queries0 :
  hoare [RawSigner(Independent).sign :
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ Independent.queries=queries0 ==>
    extends h0 Independent.rawhistory /\ extends s0 Independent.secrethistory /\
    appended_query_history h0 queries0 Independent.rawhistory Independent.queries].
proof.
  conseq (complete_signer_histories RawSigner s0 h0)
    (complete_signer_appended_queries RawSigner h0 queries0);
    smt(extends_refl appended_query_history_initial).
qed.

lemma signer_ordinary_exception_evidence seed0 h0 queries0 :
  hoare [RawSigner(Independent).sign :
    seed=seed0 /\ size seed0=32 /\ size root=32 /\ size message=32 /\ size shuffle=32 /\
    Independent.rawhistory=h0 /\ Independent.queries=queries0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs h0 Independent.rawhistory Independent.secrethistory seed0 /\
    exceptional_fors_count Independent.queries<=exceptional_fors_count queries0+2 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  conseq (raw_signer_sign_ordinary_inputs seed0 h0)
    (raw_signer_sign_exception_bound (exceptional_fors_count queries0));
    smt(ordinary_new_inputs_initial).
qed.

lemma nonordinary_signer_valid_count seed0 q :
  hoare [RawSigner(Independent).sign :
    seed=seed0 /\ size seed0=32 /\ size root=32 /\ size message=32 /\ size shuffle=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q+2 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  exists* Independent.rawhistory,Independent.secrethistory,Independent.queries; elim* => h0 s0 queries0.
  conseq (signer_histories_appended h0 s0 queries0)
    (signer_ordinary_exception_evidence seed0 h0 queries0);
    smt(nonordinary_count_sign_suffix).
qed.

lemma verifier_histories_appended h0 s0 queries0 :
  hoare [RawSigner(Independent).verify :
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ Independent.queries=queries0 ==>
    extends h0 Independent.rawhistory /\ extends s0 Independent.secrethistory /\
    appended_query_history h0 queries0 Independent.rawhistory Independent.queries].
proof.
  conseq (public_verifier_extends_histories RawSigner h0 s0)
    (public_verifier_appended_queries RawSigner h0 queries0);
    smt(extends_refl appended_query_history_initial).
qed.

lemma nonordinary_verifier_count seed0 q :
  hoare [RawSigner(Independent).verify :
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q ==>
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q+771].
proof.
  exists* Independent.rawhistory,Independent.secrethistory,Independent.queries; elim* => h0 s0 queries0.
  conseq (verifier_histories_appended h0 s0 queries0) (signer_verify_public_cost (size queries0));
    smt(nonordinary_count_public_suffix).
qed.
