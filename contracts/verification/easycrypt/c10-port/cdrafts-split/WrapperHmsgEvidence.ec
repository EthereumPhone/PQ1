(* Transfer wrapper evidence into the exact accepted-entry memo game. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog WrapperQueryDriver.
require import IndependentWidths ExposureSupport ExposureWidths WrapperActualPartition.
require import AcceptedPrefixSampling HmsgMemoOracle HmsgPoolRecords HmsgPoolGame CoveredOutputPool.
require import WrapperHmsgCount WrapperHmsgMetadata.

lemma hmsg_wrapper_byte_count
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-HmsgMemo,-AcceptedSamples}) qr qs :
  0<=qr => 0<=qs =>
  hoare[HmsgGame(WrapperQueryContext(WrapperByteLift(A))).run : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls<=qr+3*qs+1].
proof.
  move=> hr hs; proc; call (hmsg_wrapper_query_context_count (WrapperByteLift(A)) qr qs hr hs).
  inline HmsgMemo(AcceptedSamples).init AcceptedSamples.init;
    auto; rewrite /independent_tables_valid /valid_history; smt(emptyE).
qed.
lemma hmsg_wrapper_byte_metadata
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-HmsgMemo,-AcceptedSamples}) :
  hoare[HmsgGame(WrapperQueryContext(WrapperByteLift(A))).run : true ==>
    size WrapperSession.seed=32 /\ size WrapperSession.root=32 /\ logged_message_width ExposureLog.entries].
proof.
  proc; call (hmsg_wrapper_query_context_metadata (WrapperByteLift(A))).
  inline HmsgMemo(AcceptedSamples).init AcceptedSamples.init;
    auto; rewrite /independent_tables_valid /valid_history; smt(emptyE).
qed.
lemma hmsg_wrapper_byte_history
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-HmsgMemo,-AcceptedSamples}) qs :
  0<=qs =>
  hoare[HmsgGame(WrapperQueryContext(WrapperByteLift(A))).run : WrapperLimits.sign_cap=qs ==>
    exposures_supported HmsgMemo.rawhistory HmsgMemo.secrethistory WrapperSession.seed WrapperSession.root ExposureLog.entries /\
    exposures_width ExposureLog.entries].
proof.
  move=> hs.
  have he : equiv[HmsgGame(WrapperQueryContext(WrapperByteLift(A))).run ~ IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run :
    ={glob WrapperQueryContext(WrapperByteLift(A))} ==>
    HmsgMemo.rawhistory{1}=Independent.rawhistory{2} /\
    HmsgMemo.secrethistory{1}=Independent.secrethistory{2} /\
    ={glob WrapperSession,glob ExposureLog}].
  + symmetry; conseq (hmsg_game_projection (WrapperQueryContext(WrapperByteLift(A)))); smt().
  conseq he (wrapper_byte_typed_canonical_history A qs hs); smt().
qed.
