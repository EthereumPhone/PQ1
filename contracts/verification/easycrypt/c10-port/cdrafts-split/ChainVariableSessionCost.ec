(* Variable-candidate accounting for the actual opening-redacted chain backend. *)
require import AllCore List.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RoleGrindCost.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainSessionView RedactedChainOracle ChainVariableKeygenCost ChainVariableSignerCost.

require import LeafCandidateCount LeafGrindingCandidates.

op chain_candidate_budget qr qs = 155135+qr+qs*364892+771.
lemma chain_candidate_budget_ge0 qr qs : 0<=qr => 0<=qs => 0<=chain_candidate_budget qr qs.
proof. rewrite /chain_candidate_budget; smt(). qed.

lemma chain_variable_preparation_cost q :
  hoare[ChainPreparation(RedactedCachedChain).run : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+155135].
proof. proc; call (chain_variable_root_public_cost q); auto; smt(). qed.

op chain_variable_session_accounting q calls limit signs signlimit queries =
  0<=calls<=limit /\ 0<=signs<=signlimit /\
  queries<=q+calls+signs*(364892).

lemma chain_variable_session_hash_cost q :
  hoare[ChainExposureSession(RedactedCachedChain).hash :
    chain_variable_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (leaf_variable_count Independent.queries) ==> chain_variable_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (leaf_variable_count Independent.queries)].
proof.
  proc; inline FullSession(ChainPrefix(RedactedCachedChain)).hash; if.
  + rcondt 4; first by auto.
    wp; exists* Independent.queries; elim* => qs;
      call (leaf_variable_hash_bound (leaf_variable_count qs)); auto;
      rewrite /chain_variable_session_accounting; smt().
  rcondf 3; first by auto.
  auto.
qed.
lemma chain_variable_session_sign_cost q :
  hoare[ChainExposureSession(RedactedCachedChain).sign :
    chain_variable_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (leaf_variable_count Independent.queries) ==> chain_variable_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (leaf_variable_count Independent.queries)].
proof.
  proc; inline ChainSession(RedactedCachedChain).sign; wp; sp 4; if; last by auto.
  wp; exists* Independent.queries; elim* => qs;
    call (chain_variable_signer_sign_public_cost (leaf_variable_count qs)); auto;
    rewrite /chain_variable_session_accounting; smt().
qed.
lemma chain_variable_client_cost
  (A <: FullClient {-FullSession,-Independent,-ExposureLog,-ClientQueryLog}) q :
  hoare[A(ChainExposureSession(RedactedCachedChain)).run :
    chain_variable_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (leaf_variable_count Independent.queries) ==> chain_variable_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (leaf_variable_count Independent.queries)].
proof.
  proc (chain_variable_session_accounting q FullSession.raw_calls FullSession.raw_limit
      FullSession.sign_calls FullSession.sign_limit (leaf_variable_count Independent.queries)) => //.
  + exact (chain_variable_session_hash_cost q).
  exact (chain_variable_session_sign_cost q).
qed.
lemma chain_variable_driver_cost
  (A <: FullClient {-FullSession,-Independent,-ExposureLog,-ClientQueryLog}) q qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare[ChainQueryDriver(A,RedactedCachedChain).run :
    qr=qr0 /\ qs=qs0 /\ leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+qr0+qs0*(364892)+771].
proof.
  move=> hr hs; proc; seq 5 :
    (leaf_variable_count Independent.queries<=q+qr0+qs0*(364892)).
  + call (chain_variable_client_cost A q); wp;
      inline FullSession(ChainPrefix(RedactedCachedChain)).init;
      auto; rewrite /chain_variable_session_accounting /signing_budget; smt().
  sp 2; if; last by auto; smt().
  exists* Independent.queries; elim* => xs;
    call (chain_variable_signer_verify_public_cost (leaf_variable_count xs)); auto; smt().
qed.
lemma chain_variable_context_cost
  (A <: FullClient {-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare[ChainQueryContext(A,RedactedCachedChain).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\ leaf_variable_count Independent.queries<=0 ==>
    leaf_variable_count Independent.queries<=155135+qr+qs*(364892)+771].
proof.
  move=> hr hs; proc; call (chain_variable_driver_cost A 155135 qr qs hr hs).
  call (chain_variable_preparation_cost 0); auto.
qed.
