(* The initialized adaptive wrapper pays for every admitted attempt, including
   refusal, while the final output contributes at most 86 WOTS candidates. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawSigner.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog.
require import ChainValueView RedactedChainOracle LeafCandidateCount LeafGrindingCandidates.
require import ChainVariableSignerCost ChainVariableSessionCost WrapperWotsCandidateCost.
require import WrapperWotsReleaseSession WrapperWotsChainContext.

op wrapper_wots_candidate_budget qr qs = 155135+qr+qs*727934+771.
op wrapper_wots_candidate_accounting q calls limit signs signlimit queries =
  0<=calls<=limit /\ 0<=signs<=signlimit /\ queries<=q+calls+727934*signs.

lemma wrapper_wots_candidate_budget_ge0 qr qs :
  0<=qr => 0<=qs => 0<=wrapper_wots_candidate_budget qr qs.
proof. rewrite /wrapper_wots_candidate_budget; smt(). qed.

lemma wrapper_wots_hash_candidate_accounting q :
  hoare [WrapperWotsReleaseExposure(ChainPrefix(RedactedCachedChain),RedactedCachedChain).hash :
    wrapper_wots_candidate_accounting q WrapperSession.raw_calls WrapperSession.raw_limit
      WrapperSession.sign_calls WrapperSession.sign_limit (leaf_variable_count Independent.queries) ==>
    wrapper_wots_candidate_accounting q WrapperSession.raw_calls WrapperSession.raw_limit
      WrapperSession.sign_calls WrapperSession.sign_limit (leaf_variable_count Independent.queries)].
proof.
  proc; inline WrapperSession(ChainPrefix(RedactedCachedChain)).hash; if.
  + rcondt 4; first by auto.
    wp; exists* Independent.queries; elim* => qs;
      call (leaf_variable_hash_bound (leaf_variable_count qs)); auto;
      rewrite /wrapper_wots_candidate_accounting; smt().
  rcondf 3; first by auto.
  auto.
qed.

lemma wrapper_wots_session_candidate_accounting q :
  hoare [WrapperWotsReleaseSession(ChainPrefix(RedactedCachedChain),RedactedCachedChain).sign :
    wrapper_wots_candidate_accounting q WrapperSession.raw_calls WrapperSession.raw_limit
      WrapperSession.sign_calls WrapperSession.sign_limit (leaf_variable_count Independent.queries) ==>
    wrapper_wots_candidate_accounting q WrapperSession.raw_calls WrapperSession.raw_limit
      WrapperSession.sign_calls WrapperSession.sign_limit (leaf_variable_count Independent.queries)].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* Independent.queries; elim* => qs.
  call (wrapper_wots_sign_candidate_cost (leaf_variable_count qs)); auto;
    rewrite /wrapper_wots_candidate_accounting; smt().
qed.

lemma wrapper_wots_exposure_candidate_accounting q :
  hoare [WrapperWotsReleaseExposure(ChainPrefix(RedactedCachedChain),RedactedCachedChain).sign :
    wrapper_wots_candidate_accounting q WrapperSession.raw_calls WrapperSession.raw_limit
      WrapperSession.sign_calls WrapperSession.sign_limit (leaf_variable_count Independent.queries) ==>
    wrapper_wots_candidate_accounting q WrapperSession.raw_calls WrapperSession.raw_limit
      WrapperSession.sign_calls WrapperSession.sign_limit (leaf_variable_count Independent.queries)].
proof. proc; wp; call (wrapper_wots_session_candidate_accounting q); auto. qed.

lemma wrapper_wots_client_candidate_accounting
  (A <: WrapperClient {-WrapperSession,-Independent,-ExposureLog,-ClientQueryLog}) q :
  hoare [A(WrapperWotsReleaseExposure(ChainPrefix(RedactedCachedChain),RedactedCachedChain)).run :
    wrapper_wots_candidate_accounting q WrapperSession.raw_calls WrapperSession.raw_limit
      WrapperSession.sign_calls WrapperSession.sign_limit (leaf_variable_count Independent.queries) ==>
    wrapper_wots_candidate_accounting q WrapperSession.raw_calls WrapperSession.raw_limit
      WrapperSession.sign_calls WrapperSession.sign_limit (leaf_variable_count Independent.queries)].
proof.
  proc (wrapper_wots_candidate_accounting q WrapperSession.raw_calls WrapperSession.raw_limit
    WrapperSession.sign_calls WrapperSession.sign_limit (leaf_variable_count Independent.queries)) => //.
  + exact (wrapper_wots_hash_candidate_accounting q).
  exact (wrapper_wots_exposure_candidate_accounting q).
qed.

lemma wrapper_wots_driver_candidate_cost
  (A <: WrapperClient {-WrapperSession,-Independent,-ExposureLog,-ClientQueryLog}) q qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare [WrapperWotsReleaseDriver(A,ChainPrefix(RedactedCachedChain),RedactedCachedChain).run :
    qr=qr0 /\ qs=qs0 /\ leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+qr0+qs0*727934+771].
proof.
  move=> hr hs; proc; seq 5 : (leaf_variable_count Independent.queries<=q+qr0+qs0*727934).
  + call (wrapper_wots_client_candidate_accounting A q); wp;
      inline WrapperSession(ChainPrefix(RedactedCachedChain)).init;
      auto; rewrite /wrapper_wots_candidate_accounting; smt().
  sp 2; if; last by auto; smt().
  exists* Independent.queries; elim* => xs.
  call (chain_variable_signer_verify_public_cost (leaf_variable_count xs)); auto; smt().
qed.

lemma wrapper_wots_context_candidate_cost
  (A <: WrapperClient {-WrapperSession,-Independent,-ExposureLog,-ClientQueryLog,-WrapperLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare [WrapperChainWotsContext(A,RedactedCachedChain).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\ leaf_variable_count Independent.queries<=0 ==>
    leaf_variable_count Independent.queries<=wrapper_wots_candidate_budget qr qs].
proof.
  move=> hr hs; proc; call (wrapper_wots_driver_candidate_cost A 155135 qr qs hr hs).
  call (chain_variable_preparation_cost 0); auto; rewrite /wrapper_wots_candidate_budget; smt().
qed.

lemma wrapper_wots_candidates_variable_budget
  (A <: WrapperByteClient {-WrapperSession,-Independent,-ExposureLog,-ClientQueryLog,-WrapperLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare [WrapperChainWotsCandidates(A,RedactedCachedChain).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\ leaf_variable_count Independent.queries<=0 ==>
    leaf_variable_count Independent.queries<=wrapper_wots_candidate_budget qr qs].
proof.
  move=> hr hs; proc; wp; call (wrapper_wots_context_candidate_cost (WrapperByteLift(A)) qr qs hr hs); auto.
qed.
