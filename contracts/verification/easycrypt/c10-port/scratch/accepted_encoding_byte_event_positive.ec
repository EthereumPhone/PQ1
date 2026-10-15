require import AllCore List FMap StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import FullSession FullPrefix ByteSession BytePublicCollision.
require import ExposureLog ExposureDriver ClientQueryLog ClientQueryDriver.
require import EncodingMemoOracle AcceptedWotsCollision AcceptedEncodingPool AcceptedEncodingGame AcceptedEncodingCharge FullDigestPrefixSampling.
require import ByteAcceptedEncodingCharge.
require import ByteEncodingCharge.

lemma checked (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Physical,-EncodingMemo,-FullDigestSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    accepted_wots_encoding_collision Independent.rawhistory] <=
    accepted_encoding_charge (full_public_budget qr qs).
proof.
  move=> hr hs hraw hsign; exact (query_byte_accepted_encoding_collision A qr qs &m hr hs hraw hsign).
qed.
