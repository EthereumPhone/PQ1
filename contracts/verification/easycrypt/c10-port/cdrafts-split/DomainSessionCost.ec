(* A complete adaptive session budget for the conservative node domain. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes.
require import RawKeygen RawKeygenCost KeygenExhaustion RawSigner FullSession FullPrefix ByteSession.
require import IndependentWidths ExposureWidths DomainQueryCount DomainSignerCost.

op node_public_budget qr qs = 155135+qr+qs*364892+771.

lemma node_public_budget_nonnegative qr qs :
  0<=qr => 0<=qs => 0<=node_public_budget qr qs.
proof. rewrite /node_public_budget; smt(). qed.
lemma node_public_budget_le_full qr qs :
  0<=qs => node_public_budget qr qs<=full_public_budget qr qs.
proof. rewrite /node_public_budget /full_public_budget /signing_budget; smt(). qed.

lemma domain_hash_valid_bound q :
  hoare[Independent.hash : independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    node_query_count Independent.queries<=q ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    node_query_count Independent.queries<=q+1].
proof. conseq independent_hash_width (domain_hash_bound q); smt(). qed.

lemma domain_signer_valid_cost q :
  hoare[RawSigner(Independent).sign : size seed=32 /\ size root=32 /\ size message=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    node_query_count Independent.queries<=q ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    node_query_count Independent.queries<=q+364892].
proof. conseq (complete_signer_valid RawSigner) (domain_signer_sign_cost q); smt(). qed.

lemma domain_full_client_cost (A <: FullClient {-FullSession,-Independent}) q0 :
  hoare[A(FullSession(Independent)).run :
    size FullSession.seed=32 /\ size FullSession.root=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    node_query_count Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*364892 ==>
    size FullSession.seed=32 /\ size FullSession.root=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    node_query_count Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*364892].
proof.
  proc (size FullSession.seed=32 /\ size FullSession.root=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    node_query_count Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*364892) => //.
  + proc; sp 1; if; last by auto.
    wp; exists* Independent.queries; elim*=> qs;
      call (domain_hash_valid_bound (node_query_count qs)); auto; smt().
  proc; sp 1; if; last by auto.
  wp; exists* Independent.queries; elim*=> qs;
    call (domain_signer_valid_cost (node_query_count qs)); auto; smt().
qed.

lemma domain_full_driver_cost (A <: FullClient {-FullSession,-Independent}) q0 qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare[FullDriver(A,Independent).run : size seed=32 /\ size root=32 /\ qr=qr0 /\ qs=qs0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    node_query_count Independent.queries<=q0 ==>
    node_query_count Independent.queries<=q0+qr0+qs0*364892+771].
proof.
  move=> hr hs; proc; seq 2 : (node_query_count Independent.queries<=q0+qr0+qs0*364892).
  + call (domain_full_client_cost A q0); inline FullSession(Independent).init; auto; smt().
  sp 1; if; last by auto; smt().
  exists* Independent.queries; elim*=> queries;
    call (domain_signer_verify_cost (node_query_count queries)); auto; smt().
qed.

lemma domain_keygen_preparation_cost :
  hoare[KeygenPreparation(PreparationView(Independent)).run : Independent.queries=[] /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    node_query_count Independent.queries<=155135 /\ size res.`3=32 /\ size res.`4=32].
proof.
  have hv : hoare[KeygenPreparation(PreparationView(Independent)).run :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
  + proc; call (width_keygen_valid RawKeygen); auto.
  conseq keygen_preparation_cost hv; smt(node_query_count_le_size).
qed.

lemma domain_full_context_cost
  (A <: FullClient {-FullSession,-Independent,-FullLimits}) qr qs :
  0<=qr => 0<=qs =>
  hoare[FullContext(A,Independent).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\
    Independent.queries=[] /\ independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    node_query_count Independent.queries<=node_public_budget qr qs].
proof.
  move=> hr hs; proc; call (domain_full_driver_cost A 155135 qr qs hr hs).
  call domain_keygen_preparation_cost; auto; rewrite /node_public_budget; smt().
qed.

lemma domain_byte_context_cost
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) qr qs :
  0<=qr => 0<=qs =>
  hoare[ByteContext(A,Independent).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\
    Independent.queries=[] /\ independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    node_query_count Independent.queries<=node_public_budget qr qs].
proof.
  move=> hr hs.
  conseq (byte_context_equiv A Independent) (domain_full_context_cost (ByteLift(A)) qr qs hr hs).
  + move=> &m hm; exists (glob A){m} qr qs KeygenInputs.message{m} KeygenInputs.public_seed{m}
      KeygenInputs.random{m} [] Independent.rawhistory{m} Independent.secrethistory{m}; smt().
  smt().
qed.

lemma domain_byte_game_cost
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) qr qs :
  0<=qr => 0<=qs =>
  hoare[IndependentGame(ByteContext(A)).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    node_query_count Independent.queries<=node_public_budget qr qs].
proof.
  move=> hr hs; proc; call (domain_byte_context_cost A qr qs hr hs).
  inline Independent.init; auto; rewrite /independent_tables_valid /valid_history; smt(FMap.emptyE).
qed.
