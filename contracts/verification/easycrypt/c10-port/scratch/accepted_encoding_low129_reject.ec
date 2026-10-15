require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Randomizer RawWots WotsAcceptanceMass.

lemma checked (d : digest) : mu full_digest (fun e=>raw_digits d=raw_digits e)=(1%r/2%r)^128.
proof.
  exact (raw_digits_atom d).
qed.
