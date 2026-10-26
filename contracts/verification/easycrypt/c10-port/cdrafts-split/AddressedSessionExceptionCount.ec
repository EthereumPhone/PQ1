(* Actual initialized ordinary byte-game budget for exceptional-address calls.
   This is NOT a bound on all fresh draws or the node-collision probability. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner RawSignerCost FullSession ByteSession VerifierHistory.
require import IndependentWidths AddressedForsException AddressedForsExceptionCount.
require import AddressedForestExceptionCount AddressedSignerExceptionCount AddressedLayerExceptionCount.

op exceptional_public_budget qr qs = qr+2*qs+771.

lemma exceptional_hash_valid_upper q :
  hoare [Independent.hash : exceptional_fors_count Independent.queries<=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries<=q+1 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  have hc : hoare [Independent.hash : exceptional_fors_count Independent.queries<=q ==>
    exceptional_fors_count Independent.queries<=q+1]
    by proc; sp 1; if; auto; smt(exceptional_fors_count_rcons b2i_le1).
  conseq hc independent_hash_width; smt().
qed.

lemma exceptional_signer_valid_upper q :
  hoare [RawSigner(Independent).sign :
    size seed=32 /\ size root=32 /\ size message=32 /\ size shuffle=32 /\
    exceptional_fors_count Independent.queries<=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries<=q+2 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  exists* Independent.queries; elim* => queries.
  conseq (raw_signer_sign_exception_bound (exceptional_fors_count queries)); smt().
qed.

lemma exceptional_hash_ignored_monotone k :
  hoare [Independent.hash : k<=size Independent.queries-exceptional_fors_count Independent.queries ==>
    k<=size Independent.queries-exceptional_fors_count Independent.queries].
proof. proc; sp 1; if; auto; smt(size_rcons exceptional_fors_count_rcons b2i_le1). qed.

lemma exceptional_verifier_ignored_monotone (V <: PublicVerifier {-Independent}) k :
  hoare [V(Independent).verify : k<=size Independent.queries-exceptional_fors_count Independent.queries ==>
    k<=size Independent.queries-exceptional_fors_count Independent.queries].
proof.
  proc (k<=size Independent.queries-exceptional_fors_count Independent.queries) => //.
  exact (exceptional_hash_ignored_monotone k).
qed.

lemma exceptional_verifier_upper q :
  hoare [RawSigner(Independent).verify : exceptional_fors_count Independent.queries<=q ==>
    exceptional_fors_count Independent.queries<=q+771].
proof.
  exists* Independent.queries; elim* => queries.
  conseq (signer_verify_public_cost (size queries))
    (exceptional_verifier_ignored_monotone RawSigner (size queries-exceptional_fors_count queries)); smt().
qed.

lemma exceptional_full_client_cost (A <: FullClient {-FullSession,-Independent}) q0 :
  hoare [A(FullSession(Independent)).run :
    size FullSession.seed=32 /\ size FullSession.root=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    exceptional_fors_count Independent.queries<=q0+FullSession.raw_calls+2*FullSession.sign_calls ==>
    size FullSession.seed=32 /\ size FullSession.root=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    exceptional_fors_count Independent.queries<=q0+FullSession.raw_calls+2*FullSession.sign_calls].
proof.
  proc (size FullSession.seed=32 /\ size FullSession.root=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    exceptional_fors_count Independent.queries<=q0+FullSession.raw_calls+2*FullSession.sign_calls) => //.
  + proc; sp 1; if; last by auto.
    wp; exists* Independent.queries; elim* => queries;
      call (exceptional_hash_valid_upper (exceptional_fors_count queries)); auto; smt().
  proc; sp 1; if; last by auto.
  wp; exists* Independent.queries; elim* => queries;
    call (exceptional_signer_valid_upper (exceptional_fors_count queries)); auto; smt().
qed.

lemma exceptional_full_driver_cost (A <: FullClient {-FullSession,-Independent}) q0 qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare [FullDriver(A,Independent).run :
    size seed=32 /\ size root=32 /\ qr=qr0 /\ qs=qs0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    exceptional_fors_count Independent.queries<=q0 ==>
    exceptional_fors_count Independent.queries<=q0+qr0+2*qs0+771].
proof.
  move=> hr hs; proc; seq 2 : (exceptional_fors_count Independent.queries<=q0+qr0+2*qs0).
  + call (exceptional_full_client_cost A q0); inline FullSession(Independent).init; auto; smt().
  sp 1; if; last by auto; smt().
  call (exceptional_verifier_upper (q0+qr0+2*qs0)); auto.
qed.

lemma exceptional_keygen_preparation_cost :
  hoare [KeygenPreparation(PreparationView(Independent)).run :
    Independent.queries=[] /\ independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    exceptional_fors_count Independent.queries=0 /\ size res.`3=32 /\ size res.`4=32].
proof.
  have hc : hoare [KeygenPreparation(PreparationView(Independent)).run :
    Independent.queries=[] /\ independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    exceptional_fors_count Independent.queries=0].
  + proc; call (raw_keygen_root_exceptions 0); auto;
      rewrite /exceptional_fors_count /pad; smt(node_width size_cat size_nseq).
  conseq hc keygen_preparation_cost; smt().
qed.

lemma exceptional_full_context_cost
  (A <: FullClient {-FullSession,-Independent,-FullLimits}) qr qs :
  0<=qr => 0<=qs =>
  hoare [FullContext(A,Independent).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\
    Independent.queries=[] /\ independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries<=exceptional_public_budget qr qs].
proof.
  move=> hr hs; proc; call (exceptional_full_driver_cost A 0 qr qs hr hs).
  call exceptional_keygen_preparation_cost; auto; rewrite /exceptional_public_budget; smt().
qed.

lemma exceptional_byte_context_cost
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) qr qs :
  0<=qr => 0<=qs =>
  hoare [ByteContext(A,Independent).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\
    Independent.queries=[] /\ independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries<=exceptional_public_budget qr qs].
proof.
  move=> hr hs.
  conseq (byte_context_equiv A Independent) (exceptional_full_context_cost (ByteLift(A)) qr qs hr hs).
  + move=> &m hm; exists (glob A){m} qr qs KeygenInputs.message{m} KeygenInputs.public_seed{m}
      KeygenInputs.random{m} [] Independent.rawhistory{m} Independent.secrethistory{m}; smt().
  smt().
qed.

lemma exceptional_byte_game_cost
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) qr qs :
  0<=qr => 0<=qs =>
  hoare [IndependentGame(ByteContext(A)).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    exceptional_fors_count Independent.queries<=exceptional_public_budget qr qs].
proof.
  move=> hr hs; proc; call (exceptional_byte_context_cost A qr qs hr hs).
  inline Independent.init; auto; rewrite /independent_tables_valid /valid_history /exceptional_fors_count;
    smt(FMap.emptyE).
qed.
