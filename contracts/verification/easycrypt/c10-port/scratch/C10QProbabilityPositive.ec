require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess RawTrial RTailFresh GrindExhaustion.
require import AcceptedSampling AcceptedCoverage GrindJointCoverage SignerReturned.

lemma complete_probability p q0 seed root random message shuffle &m :
  0 <= q0 => size Independent.queries{m} = q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  future_fresh Independent.secrethistory{m} random message 0 =>
  size seed = 32 => size root = 32 =>
  Pr[SignatureDigestEvent.run(p,seed,root,random,message,shuffle) @ &m : res] <=
    accepted_probability p + revisit_charge q0.
proof. exact (signature_digest_bound p q0 seed root random message shuffle &m). qed.

lemma joint_probability opened target : size target = 18 =>
  accepted_probability
    (fun d => prior_covered opened d /\ take 18 (drop 143 d) = target) =
    prior_coverage_mass opened * (1%r/2%r)^18.
proof. exact (accepted_joint_probability opened target). qed.
