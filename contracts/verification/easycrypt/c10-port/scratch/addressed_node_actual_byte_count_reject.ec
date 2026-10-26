require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner FullSession ByteSession IndependentWidths.
require import AddressedOrdinaryInputs AddressedOrdinaryKeygen AddressedTreeLog.
require import AddressedMemoCount AddressedMemoCalls AddressedSessionExceptionCount.
require import AddressedMemoSession.
lemma checked
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) qr qs :
  0<=qr => 0<=qs =>
  hoare [IndependentGame(ByteContext(A)).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    size FullSession.seed=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory FullSession.seed<=exceptional_public_budget qr qs-1].
proof. exact (nonordinary_byte_game_count A qr qs). qed.
