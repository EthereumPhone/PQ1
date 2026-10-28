require import AllCore List FMap StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import WrapperSession WrapperByteSession WrapperQueryDriver WrapperPrefixBound RawWrapperCost.
require import ExposureLog ClientQueryLog WrapperPublicCharges.
require import EncodingMemoOracle AcceptedWotsCollision AcceptedEncodingPool AcceptedEncodingGame AcceptedEncodingCharge FullDigestPrefixSampling.
import RealOrder.
require import ByteEncodingCharge PrefixGames.
require import WrapperAcceptedEncodingCharge.
lemma checked
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Physical,-EncodingMemo,-FullDigestSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
    accepted_wots_encoding_collision Independent.rawhistory] <=
    accepted_encoding_charge (wrapper_total_public_budget qr qs).
proof. exact (wrapper_query_byte_accepted_encoding_collision A qr qs &m). qed.
