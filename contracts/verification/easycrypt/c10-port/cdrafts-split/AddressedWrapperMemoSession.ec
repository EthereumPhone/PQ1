(* Initialized wrapper-session count. Every admitted attempt is charged,
   including refusals and withheld results; cached/prepopulated histories and
   the final verifier remain in the same persistent oracle experiment. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner WrapperSession ByteSession IndependentWidths.
require import AddressedOrdinaryInputs AddressedOrdinaryKeygen AddressedTreeLog.
require import AddressedMemoCount AddressedMemoCalls AddressedSessionExceptionCount.

require import WrapperByteSession AddressedMemoSession AddressedWrapperMemoCalls.

op wrapper_exceptional_public_budget qr qs = qr+775*qs+771.

lemma nonordinary_wrapper_client_count (A <: WrapperClient {-WrapperSession,-Independent}) seed0 q0 :
  hoare [A(WrapperSession(Independent)).run :
    WrapperSession.seed=seed0 /\ size seed0=32 /\ size WrapperSession.root=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q0+WrapperSession.raw_calls+775*WrapperSession.sign_calls ==>
    WrapperSession.seed=seed0 /\ size seed0=32 /\ size WrapperSession.root=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q0+WrapperSession.raw_calls+775*WrapperSession.sign_calls].
proof.
  proc (WrapperSession.seed=seed0 /\ size seed0=32 /\ size WrapperSession.root=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q0+WrapperSession.raw_calls+775*WrapperSession.sign_calls) => //.
  + proc; sp 1; if; last by auto.
    wp; exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
    call (nonordinary_hash_valid_count seed0 (nonordinary_count h0 s0 seed0)); auto; smt().
  proc; sp 1; if; last by auto.
  wp; exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  call (nonordinary_wrapper_valid_count seed0 (nonordinary_count h0 s0 seed0)); auto; smt().
qed.

lemma nonordinary_wrapper_driver_count (A <: WrapperClient {-WrapperSession,-Independent}) seed0 q0 qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare [WrapperDriver(A,Independent).run :
    seed=seed0 /\ size seed0=32 /\ size root=32 /\ qr=qr0 /\ qs=qs0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q0 ==>
    WrapperSession.seed=seed0 /\ size seed0=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q0+qr0+775*qs0+771].
proof.
  move=> hr hs; proc; seq 2 : (seed=seed0 /\ WrapperSession.seed=seed0 /\ size seed0=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q0+qr0+775*qs0).
  + call (nonordinary_wrapper_client_count A seed0 q0); inline WrapperSession(Independent).init; auto; smt().
  sp 1; if; last by auto; smt().
  call (nonordinary_verifier_count seed0 (q0+qr0+775*qs0)); auto.
qed.

lemma nonordinary_wrapper_context_count
  (A <: WrapperClient {-WrapperSession,-Independent,-WrapperLimits}) qr qs :
  0<=qr => 0<=qs =>
  hoare [WrapperContext(A,Independent).run : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\
    Independent.rawhistory=empty /\ Independent.queries=[] /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    size WrapperSession.seed=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory WrapperSession.seed<=wrapper_exceptional_public_budget qr qs].
proof.
  move=> hr hs; proc; seq 1 : (WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\
    nonordinary_count Independent.rawhistory Independent.secrethistory inputs.`3=0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size inputs.`3=32 /\ size inputs.`4=32).
  + call nonordinary_keygen_preparation_count; auto.
  exists* inputs; elim* => inputs0.
  call (nonordinary_wrapper_driver_count A inputs0.`3 0 qr qs hr hs).
  auto; rewrite /wrapper_exceptional_public_budget; smt().
qed.

lemma nonordinary_wrapper_byte_context_count
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Independent}) qr qs :
  0<=qr => 0<=qs =>
  hoare [WrapperByteContext(A,Independent).run : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\
    Independent.rawhistory=empty /\ Independent.queries=[] /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    size WrapperSession.seed=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory WrapperSession.seed<=wrapper_exceptional_public_budget qr qs].
proof.
  move=> hr hs.
  conseq (wrapper_byte_context_equiv A Independent) (nonordinary_wrapper_context_count (WrapperByteLift(A)) qr qs hr hs).
  + move=> &m hm; exists (glob A){m} KeygenInputs.message{m} KeygenInputs.public_seed{m}
      KeygenInputs.random{m} [] Independent.rawhistory{m} Independent.secrethistory{m} qr qs; smt().
  smt().
qed.

lemma nonordinary_wrapper_byte_game_count
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Independent}) qr qs :
  0<=qr => 0<=qs =>
  hoare [IndependentGame(WrapperByteContext(A)).run : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==>
    size WrapperSession.seed=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory WrapperSession.seed<=wrapper_exceptional_public_budget qr qs].
proof.
  move=> hr hs; proc; call (nonordinary_wrapper_byte_context_count A qr qs hr hs).
  inline Independent.init; auto; rewrite /independent_tables_valid /valid_history; smt(FMap.emptyE).
qed.
