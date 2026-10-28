require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import WrapperSession WrapperByteSession WrapperQueryDriver IndependentWidths.
require import WotsAcceptedPrefix WotsMemoOracle WotsPoolGame WotsSessionCount WrapperWotsCount.
require import WotsByteCount.
lemma checked
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-WotsMemo,-WotsAcceptedSamples}) qr qs :
  0<=qr => 0<=qs =>
  hoare[WotsMemoGame(ClientQueryContext(ByteLift(A))).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls<=qr+4*qs+2].
proof. exact (wots_census_byte_count A qr qs). qed.
