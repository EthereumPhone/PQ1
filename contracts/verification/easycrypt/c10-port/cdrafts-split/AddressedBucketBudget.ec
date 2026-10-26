(* Exact-key combinatorics at the actual initialized byte-game boundary.
   The collision-probability refinement is a separate proof obligation. *)
require import AllCore List FSet FMap.
require import C10RawOracle PrefixGuess PrefixIdeal KeygenExhaustion FullSession ByteSession.
require import AddressedMemoCount AddressedMemoSession AddressedBuckets AddressedSessionExceptionCount.

lemma nonordinary_bucket_budget h s seed r :
  size seed=32 => nonordinary_count h s seed<=r =>
  0<=addressed_excess h<=r /\ forall label, card (addressed_bucket h label)<=r+1.
proof.
  move=> hs hr; split; first smt(addressed_excess_nonnegative addressed_excess_bound).
  move=> label; smt(addressed_bucket_bound).
qed.

lemma byte_game_addressed_bucket_budget
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) qr qs :
  0<=qr => 0<=qs =>
  hoare [IndependentGame(ByteContext(A)).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    0<=addressed_excess Independent.rawhistory<=exceptional_public_budget qr qs /\
    forall label, card (addressed_bucket Independent.rawhistory label)<=exceptional_public_budget qr qs+1].
proof.
  move=> hr hs; conseq (nonordinary_byte_game_count A qr qs hr hs); smt(nonordinary_bucket_budget).
qed.
