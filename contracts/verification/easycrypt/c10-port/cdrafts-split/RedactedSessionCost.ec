(* Adaptive byte-session query accounting survives chain caching and opening redaction. *)
require import AllCore List.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RoleGrindCost.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainSessionView RedactedChainOracle RedactedKeygenCost RedactedSignerCost.

lemma redacted_preparation_cost q :
  hoare[ChainPreparation(RedactedCachedChain).run : size Independent.queries=q ==>
    size Independent.queries<=q+155135].
proof. proc; call (redacted_root_public_cost q); auto; smt(). qed.

op redacted_session_accounting q calls limit signs signlimit queries =
  0<=calls<=limit /\ 0<=signs<=signlimit /\
  queries<=q+calls+signs*(3*signing_budget+364892).

lemma redacted_session_hash_cost q :
  hoare[ChainExposureSession(RedactedCachedChain).hash :
    redacted_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (size Independent.queries) ==> redacted_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (size Independent.queries)].
proof.
  proc; inline FullSession(ChainPrefix(RedactedCachedChain)).hash; if.
  + rcondt 4; first by auto.
    wp; exists* Independent.queries; elim* => qs;
      call (independent_hash_count (size qs)); auto;
      rewrite /redacted_session_accounting; smt().
  rcondf 3; first by auto.
  auto.
qed.
lemma redacted_session_sign_cost q :
  hoare[ChainExposureSession(RedactedCachedChain).sign :
    redacted_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (size Independent.queries) ==> redacted_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (size Independent.queries)].
proof.
  proc; inline ChainSession(RedactedCachedChain).sign; wp; sp 4; if; last by auto.
  wp; exists* Independent.queries; elim* => qs;
    call (redacted_signer_sign_public_cost (size qs)); auto;
    rewrite /redacted_session_accounting; smt().
qed.
lemma redacted_client_cost
  (A <: FullClient {-FullSession,-Independent,-ExposureLog,-ClientQueryLog}) q :
  hoare[A(ChainExposureSession(RedactedCachedChain)).run :
    redacted_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (size Independent.queries) ==> redacted_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (size Independent.queries)].
proof.
  proc (redacted_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (size Independent.queries)) => //.
  + exact (redacted_session_hash_cost q).
  exact (redacted_session_sign_cost q).
qed.
lemma redacted_driver_cost
  (A <: FullClient {-FullSession,-Independent,-ExposureLog,-ClientQueryLog}) q qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare[ChainQueryDriver(A,RedactedCachedChain).run :
    qr=qr0 /\ qs=qs0 /\ size Independent.queries<=q ==>
    size Independent.queries<=q+qr0+qs0*(3*signing_budget+364892)+771].
proof.
  move=> hr hs; proc; seq 5 :
    (size Independent.queries<=q+qr0+qs0*(3*signing_budget+364892)).
  + call (redacted_client_cost A q); wp;
      inline FullSession(ChainPrefix(RedactedCachedChain)).init;
      auto; rewrite /redacted_session_accounting /signing_budget; smt().
  sp 2; if; last by auto; smt().
  exists* Independent.queries; elim* => xs;
    call (redacted_signer_verify_public_cost (size xs)); auto; smt().
qed.
lemma redacted_context_cost
  (A <: FullClient {-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare[ChainQueryContext(A,RedactedCachedChain).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\ size Independent.queries=0 ==>
    size Independent.queries<=155135+qr+qs*(3*signing_budget+364892)+771].
proof.
  move=> hr hs; proc; call (redacted_driver_cost A 155135 qr qs hr hs).
  call (redacted_preparation_cost 0); auto.
qed.
