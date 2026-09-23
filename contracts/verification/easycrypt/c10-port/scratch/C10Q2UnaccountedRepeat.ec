require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixIdeal FullSession ByteSession.
require import RawTrial RTailFresh GrindExhaustion AcceptedSampling.
require import GrindTrace ClassifiedHistory ClassifiedSession ClassifiedBound.
require import SessionDigest ByteHistory FullHistory SignerTrace RawSigner.
lemma novel_probability p random message shuffle &m :
  live_classified Independent.secrethistory{m} Independent.rawhistory{m}
    FullSession.seed{m} FullSession.root{m} FullSession.failed{m} =>
  !FullSession.failed{m} =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  size message = 32 => size FullSession.seed{m} = 32 => size FullSession.root{m} = 32 =>
  Pr[SessionDigestEvent.run(p,random,message,shuffle) @ &m : res] <=
    accepted_probability p + revisit_charge (size Independent.queries{m}).
proof. exact (session_novel_digest_bound p random message shuffle &m). qed.
