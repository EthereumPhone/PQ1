(* Byte-client instantiation of the selective experiment. This still requires
   its transformed-game query budget; it is not the original EUF bound. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawSigner FullSession ByteSession ExposureLog ClientQueryLog.
require import LeafCommitmentHybrid LeafOpeningBound TargetOracleSplit TargetPrivateBound LeafBoundState.
require import TargetByteView TargetByteLossless.

lemma byte_selective_private_guess_bound
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
    (q+12)%r*(1%r/2%r)^128.
proof.
  move=> ha hq hb.
  apply (adaptive_selective_private_guess_at_state (TargetByteCandidates(A)) q 12 &m) => //.
  + move=> O hh hd hl hs; exact (target_byte_candidates_lossless A O ha hh hd hl hs).
  conseq hb (target_byte_candidate_count A (TargetKernelAdapter(RedactedLeafOpening(Independent)))); smt().
qed.
