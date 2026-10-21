(* Boundary and nonvacuity witnesses for native signing availability.
   The constant test oracle is lossless but is not an initialized random oracle
   or a concrete hash backend. Prefilled-table examples retain that boundary. *)
require import AllCore List Distr FMap StdOrder RadixEncoding.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames.
require import RawKeygen RawWots WotsUnreturnedCut KeygenPrefixes KeygenExhaustion.
require import RawSigner FullSession ByteSession RObservedSigner FullRSession.
require import MemoRejectCompletion WotsRejectDomain ByteTotalAvailability AvailabilityNumerics.
import RField RealOrder.

lemma total_deployed_schedule_distinct seed layer tree kp message :
  uniq (wots_count_schedule
    (wots_context_stem seed (wots_context_bytes layer tree kp message)) signing_budget).
proof. apply wots_count_schedule_unique; exact signing_budget_fits_wots_schedule. qed.

lemma total_zero_trial_event accept h stem :
  memo_complete_rejection accept h (wots_count_schedule stem 0).
proof. by rewrite /wots_count_schedule range_geq // /memo_complete_rejection /=. qed.

lemma total_duplicate_schedule_excluded (x : raw_input) : !uniq [x;x].
proof. by []. qed.

lemma total_accepted_prefill accept (h : (raw_input,digest) fmap) x d : accept d =>
  memo_reject_completion accept h.[x <- d] [x]=0%r /\
  !memo_complete_rejection accept h.[x <- d] [x].
proof.
  by move=> ha; rewrite /memo_reject_completion /= /memo_reject_weight /memo_complete_rejection /=
    mem_set get_set_sameE /= ha /=.
qed.

lemma total_rejected_prefill accept (h : (raw_input,digest) fmap) x d : !accept d =>
  memo_reject_completion accept h.[x <- d] [x]=1%r /\
  memo_complete_rejection accept h.[x <- d] [x].
proof.
  by move=> ha; rewrite /memo_reject_completion /= /memo_reject_weight /memo_complete_rejection /=
    mem_set get_set_sameE /= ha /=.
qed.

lemma wots_test_digest_rejected : !count_accepts (nseq 256 true).
proof.
  apply/negP => /accepted_has_nonmax_digit [i [hi hd]].
  have he : digit 3 (nseq 256 true) i=7 by rewrite digit3 !nth_nseq; smt().
  smt().
qed.

lemma total_rejected_prefill_nonvacuous (x : raw_input) :
  memo_reject_completion count_accepts empty.[x <- nseq 256 true] [x]=1%r /\
  memo_complete_rejection count_accepts empty.[x <- nseq 256 true] [x].
proof. exact (total_rejected_prefill count_accepts empty x (nseq 256 true) wots_test_digest_rejected). qed.

module WotsRejectTestOracle = {
  proc hash(x : raw_input) : digest = { return nseq 256 true; }
  proc wots(tail : raw_input) : digest = { return nseq 256 true; }
  proc fors(tail : raw_input) : digest = { return nseq 256 true; }
}.

lemma wots_test_count_exhausts :
  hoare[RawWots(WotsRejectTestOracle).count : true ==> res=None].
proof.
  proc; while (result=None).
  + inline WotsRejectTestOracle.hash; auto; smt(wots_test_digest_rejected).
  auto.
qed.

lemma wots_test_count_lossless : islossless RawWots(WotsRejectTestOracle).count.
proof. apply (raw_count_lossless WotsRejectTestOracle); proc; auto. qed.

lemma wots_test_signer_exhausts :
  hoare[RawWots(WotsRejectTestOracle).sign : true ==> res=None].
proof.
  proc; seq 1 : (accepted=None).
  + call wots_test_count_exhausts; auto.
  rcondf 2; auto.
qed.

lemma wots_test_signer_lossless : islossless RawWots(WotsRejectTestOracle).sign.
proof. apply (raw_sign_lossless WotsRejectTestOracle); proc; auto. qed.

lemma total_refusal_preserves_failed (O <: PrefixOracle {-FullSession}) b c :
  hoare[FullSession(O).sign : FullSession.failed=b /\ FullSession.sign_calls=c /\
    (FullSession.failed \/ size message<>32 \/
      FullSession.sign_limit<=FullSession.sign_calls) ==>
    res=None /\ FullSession.failed=b /\ FullSession.sign_calls=c].
proof. proc; rcondf 2; auto; smt(). qed.

module NoRequestByteClient (O : ByteClientOracle) = {
  proc run(seed root : raw_input) : raw_input * raw_input = { return ([],[]); }
}.

lemma total_no_request_client_lossless (O <: ByteClientOracle) :
  islossless NoRequestByteClient(O).run.
proof. proc; auto. qed.

lemma total_no_request_failure_zero &m :
  Pr[RealGame(ByteContext(NoRequestByteClient)).run() @ &m : FullSession.failed]=0%r.
proof.
  byphoare (_ : true ==> FullSession.failed) => //; hoare.
  proc; inline ByteContext(NoRequestByteClient,Physical).run
    ByteDriver(NoRequestByteClient,Physical).run NoRequestByteClient(ByteView(FullSession(Physical))).run
    FullSession(Physical).init.
  rcondf 25; first by auto.
  wp.
  call (_ : true ==> true); first by trivial.
  inline Shared.init; auto.
qed.

lemma byte_total_deployed_availability
    (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-RFailure,-Physical,-Hybrid,-Shared,-Independent}) &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  FullLimits.raw_cap{m}=2^32 => FullLimits.sign_cap{m}=2^20 =>
  Pr[RealGame(ByteContext(A)).run() @ &m : FullSession.failed] <= (1%r/2%r)^38.
proof.
  move=> ha hr hs.
  have h := byte_total_initialized_availability A (2^32) (2^20) &m ha _ _ hr hs;
    first 2 by smt(IntOrder.expr_gt0).
  smt(total_availability_numerical).
qed.
