(* Functional boundary witnesses. The constant oracle below is a test oracle,
   not a claim about an initialized random oracle or a concrete SHA backend. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawSigner FullSession RoleGrind RObservedSigner FullRSession FullRBound.
require import RawTrial ClassifiedHistory.

lemma r_empty_history_classified seed root :
  classified_history empty empty seed root.
proof. apply no_r_classified; rewrite /no_r_tails; smt(mem_empty). qed.

lemma r_request_nonvacuous : full_r_valid [] (nseq 32 0) (nseq 32 0).
proof. rewrite /full_r_valid; smt(size_nseq). qed.

lemma r_observer_initialization (O <: PrefixOracle {-FullSession,-RFailure}) :
  hoare[FullRSession(O).init : true ==>
    !RFailure.bad /\ !FullSession.failed /\ FullSession.sign_calls = 0 /\
    FullSession.raw_calls = 0 /\ FullSession.signed_messages = []].
proof. proc; inline FullSession(O).init; auto. qed.

lemma r_malformed_refusal (O <: PrefixOracle {-FullSession,-RFailure}) b g c messages :
  hoare[FullRSession(O).sign : size message <> 32 /\ RFailure.bad = b /\
    (glob O) = g /\ FullSession.sign_calls = c /\ FullSession.signed_messages = messages ==>
    res = None /\ RFailure.bad = b /\ (glob O) = g /\
    FullSession.sign_calls = c /\ FullSession.signed_messages = messages].
proof. proc; rcondf 2; auto; smt(). qed.

lemma r_cap_refusal (O <: PrefixOracle {-FullSession,-RFailure}) b g c messages :
  hoare[FullRSession(O).sign : FullSession.sign_limit <= FullSession.sign_calls /\
    RFailure.bad = b /\ (glob O) = g /\ FullSession.sign_calls = c /\
    FullSession.signed_messages = messages ==>
    res = None /\ RFailure.bad = b /\ (glob O) = g /\
    FullSession.sign_calls = c /\ FullSession.signed_messages = messages].
proof. proc; rcondf 2; auto; smt(). qed.

lemma r_failed_session_refusal (O <: PrefixOracle {-FullSession,-RFailure}) b g c messages :
  hoare[FullRSession(O).sign : FullSession.failed /\ RFailure.bad = b /\
    (glob O) = g /\ FullSession.sign_calls = c /\ FullSession.signed_messages = messages ==>
    res = None /\ FullSession.failed /\ RFailure.bad = b /\ (glob O) = g /\
    FullSession.sign_calls = c /\ FullSession.signed_messages = messages].
proof. proc; rcondf 2; auto; smt(). qed.

module RRejectTestOracle = {
  proc hash(x : raw_input) : digest = { return nseq 256 true; }
  proc derive(tail : raw_input) : digest = { return nseq 256 true; }
}.

lemma r_test_digest_rejected : !accept_digest (nseq 256 true).
proof.
  rewrite /accept_digest; apply/negP=> he.
  have ht : nth false (take 11 (drop 132 (nseq 256 true))) 0 = nth false (nseq 11 false) 0
    by rewrite he.
  move: ht; rewrite nth_take 1:// 1:// nth_drop 1:// 1:// !nth_nseq //.
qed.

lemma r_test_grind_exhausts :
  hoare[RoleGrind(RRejectTestOracle).run : true ==> res = None].
proof.
  proc; while (result = None).
  + inline RRejectTestOracle.hash RRejectTestOracle.derive; auto; smt(r_test_digest_rejected).
  auto.
qed.

lemma r_test_signer_observes_exhaustion :
  hoare[RObservedSigner(RRejectTestOracle).sign : !RFailure.bad ==>
    RFailure.bad /\ res = None].
proof.
  proc; seq 1 : (accepted = None).
  + call r_test_grind_exhausts; auto.
  rcondf 3; auto; smt().
qed.

lemma r_test_signer_lossless : islossless RObservedSigner(RRejectTestOracle).sign.
proof.
  apply (r_observed_sign_lossless RRejectTestOracle); proc; auto.
qed.

lemma r_test_admitted_failure c :
  hoare[FullRSession(RRejectTestOracle).sign :
    !FullSession.failed /\ !RFailure.bad /\ full_r_valid random message shuffle /\
    FullSession.sign_calls = c /\ c < FullSession.sign_limit ==>
    res = None /\ RFailure.bad /\ FullSession.failed /\ FullSession.sign_calls = c+1].
proof.
  proc; rcondt 2; first by auto; rewrite /full_r_valid; smt().
  wp; call r_test_signer_observes_exhaustion; auto; smt().
qed.
