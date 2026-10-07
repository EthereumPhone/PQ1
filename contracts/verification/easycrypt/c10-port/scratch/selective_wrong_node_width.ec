(* Byte-client instantiation of the selective experiment. This still requires
   its transformed-game query budget; it is not the original EUF bound. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawSigner FullSession ByteSession ExposureLog ClientQueryLog.
require import LeafCommitmentHybrid LeafOpeningBound TargetOracleSplit TargetPrivateBound LeafBoundState.
require import TargetByteView TargetByteLossless TargetByteBound.

lemma consume_byte_selective_private_bound
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -TargetConfig,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-Shared,-Independent,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState}) q &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=q =>
  hoare [TargetByteCandidates(A,TargetKernelAdapter(RedactedLeafOpening(Independent))).run :
    Independent.queries=[] /\ OtherPrivate.history=empty /\ !RedactedLeafState.revealed /\
    (glob TargetByteCandidates(A))=(glob TargetByteCandidates(A)){m} ==>
    size Independent.queries<=q] =>
  Pr[SelectivePrivateGuess(TargetByteCandidates(A)).run() @ &m : res] <=
    (q+12)%r*(1%r/2%r)^256.
proof. exact (byte_selective_private_guess_bound A q &m). qed.
