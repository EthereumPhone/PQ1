require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes.
require import RawKeygen RawKeygenCost KeygenExhaustion RawSigner FullSession FullPrefix ByteSession.
require import IndependentWidths ExposureWidths DomainQueryCount DomainSignerCost.
require import DomainSessionCost.

lemma checked (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) qr qs :
  0<=qr => 0<=qs =>
  hoare[IndependentGame(ByteContext(A)).run : FullLimits.sign_cap=qs ==>
    node_query_count Independent.queries<=node_public_budget qr qs].
proof.
  move=> hr hs; exact (domain_byte_game_cost A qr qs hr hs).
qed.
