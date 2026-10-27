require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner WrapperSession ByteSession IndependentWidths.
require import AddressedOrdinaryInputs AddressedOrdinaryKeygen AddressedTreeLog.
require import AddressedMemoCount AddressedMemoCalls AddressedSessionExceptionCount.
require import WrapperByteSession AddressedMemoSession AddressedWrapperMemoCalls.
require import AddressedWrapperMemoSession.
lemma checked
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Independent}) qr qs :
  0<=qr => 0<=qs =>
  hoare [IndependentGame(WrapperByteContext(A)).run : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==>
    size WrapperSession.seed=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory WrapperSession.seed<=wrapper_exceptional_public_budget qr qs].
proof. exact (nonordinary_wrapper_byte_game_count A qr qs). qed.
