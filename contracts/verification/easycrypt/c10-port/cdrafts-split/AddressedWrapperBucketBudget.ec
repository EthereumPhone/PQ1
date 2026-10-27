(* Exact memo buckets in the initialized wrapper experiment. *)
require import AllCore List FSet FMap.
require import C10RawOracle PrefixGuess PrefixIdeal KeygenExhaustion WrapperSession WrapperByteSession.
require import AddressedMemoCount AddressedBuckets AddressedBucketBudget AddressedWrapperMemoSession.

lemma wrapper_byte_game_addressed_bucket_budget
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Independent}) qr qs :
  0<=qr => 0<=qs =>
  hoare [IndependentGame(WrapperByteContext(A)).run : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==>
    0<=addressed_excess Independent.rawhistory<=wrapper_exceptional_public_budget qr qs /\
    forall label, card (addressed_bucket Independent.rawhistory label)<=wrapper_exceptional_public_budget qr qs+1].
proof.
  move=> hr hs; conseq (nonordinary_wrapper_byte_game_count A qr qs hr hs); smt(nonordinary_bucket_budget).
qed.
