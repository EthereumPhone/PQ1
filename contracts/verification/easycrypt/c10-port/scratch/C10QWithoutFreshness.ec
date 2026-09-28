require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess RawTrial RTailFresh GrindExhaustion.
require import AcceptedSampling SignerReturned.

lemma false_without_freshness p q0 seed root random message shuffle &m :
  0 <= q0 => size Independent.queries{m} = q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  size seed = 32 => size root = 32 =>
  Pr[SignatureDigestEvent.run(p,seed,root,random,message,shuffle) @ &m : res] <=
    accepted_probability p + revisit_charge q0.
proof.
  move=> hq hs hh hp hr.
  by apply (signature_digest_bound p q0 seed root random message shuffle &m).
qed.
