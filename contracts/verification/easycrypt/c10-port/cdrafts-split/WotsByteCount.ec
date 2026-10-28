(* Actual initialized accepted-call budgets for both public byte interfaces. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import WrapperSession WrapperByteSession WrapperQueryDriver IndependentWidths.
require import WotsAcceptedPrefix WotsMemoOracle WotsPoolGame WotsSessionCount WrapperWotsCount.

lemma wots_census_byte_count
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-WotsMemo,-WotsAcceptedSamples}) qr qs :
  0<=qr => 0<=qs =>
  hoare[WotsMemoGame(ClientQueryContext(ByteLift(A))).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls<=qr+4*qs+2].
proof.
  move=> hr hs; proc; call (wots_census_query_context_count (ByteLift(A)) qr qs hr hs).
  inline WotsMemo(WotsAcceptedSamples).init WotsAcceptedSamples.init;
    auto; rewrite /independent_tables_valid /valid_history; smt(emptyE).
qed.

lemma wots_census_wrapper_byte_count
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-WotsMemo,-WotsAcceptedSamples}) qr qs :
  0<=qr => 0<=qs =>
  hoare[WotsMemoGame(WrapperQueryContext(WrapperByteLift(A))).run : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls<=qr+10*qs+2].
proof.
  move=> hr hs; proc; call (wots_census_wrapper_query_context_count (WrapperByteLift(A)) qr qs hr hs).
  inline WotsMemo(WotsAcceptedSamples).init WotsAcceptedSamples.init;
    auto; rewrite /independent_tables_valid /valid_history; smt(emptyE).
qed.
