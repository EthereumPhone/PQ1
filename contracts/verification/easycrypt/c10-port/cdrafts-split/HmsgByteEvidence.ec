(* Byte-game evidence transferred to the exact accepted-entry memo game. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import IndependentWidths ExposureSupport ExposureWidths ActualExposurePartition.
require import AcceptedPrefixSampling HmsgMemoOracle HmsgPoolRecords HmsgPoolGame HmsgSessionCount HmsgSessionMetadata CoveredOutputPool.

lemma hmsg_byte_count
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-HmsgMemo,-AcceptedSamples}) qr qs :
  0<=qr => 0<=qs =>
  hoare[HmsgGame(ClientQueryContext(ByteLift(A))).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls<=qr+qs+1].
proof.
  move=> hr hs; proc; call (hmsg_query_context_count (ByteLift(A)) qr qs hr hs).
  inline HmsgMemo(AcceptedSamples).init AcceptedSamples.init;
    auto; rewrite /independent_tables_valid /valid_history; smt(emptyE).
qed.
lemma hmsg_byte_metadata
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-HmsgMemo,-AcceptedSamples}) :
  hoare[HmsgGame(ClientQueryContext(ByteLift(A))).run : true ==>
    size FullSession.seed=32 /\ size FullSession.root=32 /\ logged_message_width ExposureLog.entries].
proof.
  proc; call (hmsg_query_context_metadata (ByteLift(A))).
  inline HmsgMemo(AcceptedSamples).init AcceptedSamples.init;
    auto; rewrite /independent_tables_valid /valid_history; smt(emptyE).
qed.
lemma hmsg_byte_history
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-HmsgMemo,-AcceptedSamples}) qs :
  0<=qs =>
  hoare[HmsgGame(ClientQueryContext(ByteLift(A))).run : FullLimits.sign_cap=qs ==>
    exposures_supported HmsgMemo.rawhistory HmsgMemo.secrethistory FullSession.seed FullSession.root ExposureLog.entries /\
    exposures_width ExposureLog.entries].
proof.
  move=> hs.
  have he : equiv[HmsgGame(ClientQueryContext(ByteLift(A))).run ~ IndependentGame(ClientQueryContext(ByteLift(A))).run :
    ={glob ClientQueryContext(ByteLift(A))} ==>
    HmsgMemo.rawhistory{1}=Independent.rawhistory{2} /\
    HmsgMemo.secrethistory{1}=Independent.secrethistory{2} /\
    ={glob FullSession,glob ExposureLog}].
  + symmetry; conseq (hmsg_game_projection (ClientQueryContext(ByteLift(A)))); smt().
  conseq he (query_byte_typed_canonical_history A qs hs); smt().
qed.
