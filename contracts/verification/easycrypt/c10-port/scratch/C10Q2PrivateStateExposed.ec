require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixIdeal FullSession ByteSession.
require import RawTrial RTailFresh GrindExhaustion AcceptedSampling.
require import GrindTrace ClassifiedHistory ClassifiedSession ClassifiedBound.
require import SessionDigest ByteHistory FullHistory SignerTrace RawSigner.
lemma live_session (A <: ByteClient {-FullSession}) :
  hoare[IndependentGame(ByteContext(A)).run : true ==>
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed].
proof. exact (byte_game_classified A). qed.
