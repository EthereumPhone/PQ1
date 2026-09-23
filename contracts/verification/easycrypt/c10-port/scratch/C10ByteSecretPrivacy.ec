require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenExhaustion.
require import FullSession FullPrefix RawSignature RawDecode RawSignerWidths ByteSession ByteBound.
lemma missing_secret_privacy
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Hybrid,-Shared,-Independent}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0 <= qr => 0 <= qs => FullLimits.raw_cap{m} = qr => FullLimits.sign_cap{m} = qs =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <=
    Pr[IndependentGame(ByteContext(A)).run() @ &m : res] +
    (full_public_budget qr qs)%r * (1%r/2%r)^256.
proof. exact (byte_physical_to_independent A qr qs &m). qed.
