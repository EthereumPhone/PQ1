(* Actual initialized byte-game bound on distinct nonordinary public keys.
   Each raw/final call is charged once; honest signing adds at most two. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner FullSession ByteSession IndependentWidths.
require import AddressedOrdinaryInputs AddressedOrdinaryKeygen AddressedTreeLog.
require import AddressedMemoCount AddressedMemoCalls AddressedSessionExceptionCount.

lemma nonordinary_full_client_count (A <: FullClient {-FullSession,-Independent}) seed0 q0 :
  hoare [A(FullSession(Independent)).run :
    FullSession.seed=seed0 /\ size seed0=32 /\ size FullSession.root=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q0+FullSession.raw_calls+2*FullSession.sign_calls ==>
    FullSession.seed=seed0 /\ size seed0=32 /\ size FullSession.root=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q0+FullSession.raw_calls+2*FullSession.sign_calls].
proof.
  proc (FullSession.seed=seed0 /\ size seed0=32 /\ size FullSession.root=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q0+FullSession.raw_calls+2*FullSession.sign_calls) => //.
  + proc; sp 1; if; last by auto.
    wp; exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
    call (nonordinary_hash_valid_count seed0 (nonordinary_count h0 s0 seed0)); auto; smt().
  proc; sp 1; if; last by auto.
  wp; exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  call (nonordinary_signer_valid_count seed0 (nonordinary_count h0 s0 seed0)); auto; smt().
qed.

lemma nonordinary_full_driver_count (A <: FullClient {-FullSession,-Independent}) seed0 q0 qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare [FullDriver(A,Independent).run :
    seed=seed0 /\ size seed0=32 /\ size root=32 /\ qr=qr0 /\ qs=qs0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q0 ==>
    FullSession.seed=seed0 /\ size seed0=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q0+qr0+2*qs0+771].
proof.
  move=> hr hs; proc; seq 2 : (seed=seed0 /\ FullSession.seed=seed0 /\ size seed0=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q0+qr0+2*qs0).
  + call (nonordinary_full_client_count A seed0 q0); inline FullSession(Independent).init; auto; smt().
  sp 1; if; last by auto; smt().
  call (nonordinary_verifier_count seed0 (q0+qr0+2*qs0)); auto.
qed.

lemma canonical_keygen_count_zero h s seed :
  canonical_keygen_history h s seed => nonordinary_count h s seed=0.
proof.
  move=> hc; apply nonordinary_count_zero; move=> x hx.
  have ho := hc x hx; rewrite /ordinary_public_input /canonical_long_input; smt().
qed.

lemma nonordinary_keygen_preparation_count :
  hoare [KeygenPreparation(PreparationView(Independent)).run :
    Independent.rawhistory=empty /\ Independent.queries=[] /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    nonordinary_count Independent.rawhistory Independent.secrethistory res.`3=0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res.`3=32 /\ size res.`4=32].
proof. conseq keygen_preparation_initial_ordinary; smt(canonical_keygen_count_zero). qed.

lemma nonordinary_full_context_count
  (A <: FullClient {-FullSession,-Independent,-FullLimits}) qr qs :
  0<=qr => 0<=qs =>
  hoare [FullContext(A,Independent).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\
    Independent.rawhistory=empty /\ Independent.queries=[] /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    size FullSession.seed=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory FullSession.seed<=exceptional_public_budget qr qs].
proof.
  move=> hr hs; proc; seq 1 : (FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\
    nonordinary_count Independent.rawhistory Independent.secrethistory inputs.`3=0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size inputs.`3=32 /\ size inputs.`4=32).
  + call nonordinary_keygen_preparation_count; auto.
  exists* inputs; elim* => inputs0.
  call (nonordinary_full_driver_count A inputs0.`3 0 qr qs hr hs).
  auto; rewrite /exceptional_public_budget; smt().
qed.

lemma nonordinary_byte_context_count
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) qr qs :
  0<=qr => 0<=qs =>
  hoare [ByteContext(A,Independent).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\
    Independent.rawhistory=empty /\ Independent.queries=[] /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    size FullSession.seed=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory FullSession.seed<=exceptional_public_budget qr qs].
proof.
  move=> hr hs.
  conseq (byte_context_equiv A Independent) (nonordinary_full_context_count (ByteLift(A)) qr qs hr hs).
  + move=> &m hm; exists (glob A){m} qr qs KeygenInputs.message{m} KeygenInputs.public_seed{m}
      KeygenInputs.random{m} [] Independent.rawhistory{m} Independent.secrethistory{m}; smt().
  smt().
qed.

lemma nonordinary_byte_game_count
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) qr qs :
  0<=qr => 0<=qs =>
  hoare [IndependentGame(ByteContext(A)).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    size FullSession.seed=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory FullSession.seed<=exceptional_public_budget qr qs].
proof.
  move=> hr hs; proc; call (nonordinary_byte_context_count A qr qs hr hs).
  inline Independent.init; auto; rewrite /independent_tables_valid /valid_history; smt(FMap.emptyE).
qed.
