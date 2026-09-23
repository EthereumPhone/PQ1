require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixIdeal FullSession ByteSession.
require import RawTrial RTailFresh GrindExhaustion AcceptedSampling.
require import GrindTrace ClassifiedHistory ClassifiedSession ClassifiedBound.
require import SessionDigest ByteHistory FullHistory SignerTrace RawSigner.
lemma repeat_is_not_fresh s h random message seed root answer :
  completed_trace s h random message seed root answer =>
  !future_fresh s random message 0.
proof. exact (completed_trace_not_fresh s h random message seed root answer). qed.
