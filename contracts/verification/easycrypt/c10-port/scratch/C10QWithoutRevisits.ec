require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess RawTrial RTailFresh GrindExhaustion.
require import AcceptedSampling SignerReturned.

lemma false_without_revisits p q0 seed root random message shuffle &m :
  0 <= q0 => size Independent.queries{m} = q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  future_fresh Independent.secrethistory{m} random message 0 =>
  size seed = 32 => size root = 32 =>
  Pr[SignatureDigestEvent.run(p,seed,root,random,message,shuffle) @ &m : res] <=
    accepted_probability p.
proof.
  move=> hq hs hh hf hp hr.
  exact (signature_digest_bound p q0 seed root random message shuffle &m hq hs hh hf hp hr).
qed.
