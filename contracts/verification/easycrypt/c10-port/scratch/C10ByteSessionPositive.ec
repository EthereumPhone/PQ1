require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenExhaustion.
require import FullSession FullPrefix RawSignature RawDecode RawSignerWidths ByteSession ByteBound.
lemma checked_byte_roundtrip bs : size bs = 4008 => byte_values bs =>
  encode_signature (decode_signature bs) = bs.
proof. rewrite /byte_values; exact (signature_bytes_roundtrip bs). qed.
lemma checked_decoder_width bs : size bs = 4008 => signature_width (decode_signature bs).
proof. exact (decoded_signature_width bs). qed.
lemma checked_empty_bytes_rejected : !byte_signature [].
proof. by rewrite /byte_signature /=. qed.
lemma checked_budget_separation qr qs :
  full_physical_budget qr qs - full_public_budget qr qs = 22016 + qs*(C10Counter.signing_budget+70754).
proof. rewrite /full_physical_budget /full_public_budget; ring. qed.
lemma checked_byte_bound
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Physical,-Hybrid,-Shared,-Independent}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0 <= qr => 0 <= qs => FullLimits.raw_cap{m} = qr => FullLimits.sign_cap{m} = qs =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <=
    Pr[IndependentGame(ByteContext(A)).run() @ &m : res] +
    (full_public_budget qr qs)%r * (1%r/2%r)^256.
proof. exact (byte_physical_to_independent A qr qs &m). qed.
