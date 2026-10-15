require import AllCore List Distr DList DBool Ring BitEncoding RadixEncoding StdOrder StdBigop RealSeries.
require import C10RawOracle C10Randomizer RawWots WotsDigitOrder EncodingDistribution.
require import CountDS C10Surface C10SurfaceKernel.
require import WotsAcceptanceMass.

lemma checked :
  mu (full_digest `*` full_digest) (fun (de : digest * digest)=>
    count_accepts de.`1 /\ count_accepts de.`2 /\ raw_digits de.`1=raw_digits de.`2)=
    wots_acceptance_mass*(1%r/2%r)^129.
proof.
  exact accepted_encoding_pair_mass.
qed.
