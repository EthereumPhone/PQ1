(* Reuse the actual finisher's history and cost contracts. The R observer
   changes no query or failure path and cannot be read by the client. *)
require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RoleGrind RoleGrindCost.
require import RawSigner RawSignerCost RawTrial SignerRecorded RSessionHistory.
require import ClassifiedHistory ClassifiedGrind ClassifiedSigner RObservedSigner.

lemma r_observed_sign_classified seed0 root0 :
  hoare[RObservedSigner(Independent).sign :
    seed = seed0 /\ root = root0 /\ size message = 32 /\
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0 ==>
    res <> None => classified_history Independent.secrethistory Independent.rawhistory seed0 root0].
proof.
  proc; exists* random, message; elim* => random0 message0.
  seq 1 : (accepted <> None =>
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0).
  + call (role_grind_classifies seed0 root0 random0 message0); auto.
  sp 2; if; last by auto.
  call (signer_finish_classified seed0 root0); auto; smt().
qed.

lemma r_observed_sign_recorded :
  hoare[RObservedSigner(Independent).sign :
    history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof.
  proc; seq 1 : (history_recorded Independent.rawhistory Independent.queries).
  + call role_grind_recorded; auto.
  sp 2; if; last by auto.
  call signer_finish_recorded; auto.
qed.

lemma r_observed_sign_public_cost q :
  hoare[RObservedSigner(Independent).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+3*signing_budget+364892].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+signing_budget).
  + call (role_grind_public_cost q); auto; smt().
  sp 2; if; last by auto; rewrite /signing_budget; smt().
  exists* Independent.queries; elim* => queries; move=> bad.
  call (signer_finish_public_cost (size queries)); auto; smt().
qed.
