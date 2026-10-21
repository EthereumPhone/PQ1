require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RoleGrind RawSigner.
require import RawTrial ClassifiedHistory GrindExhaustion RClassifiedExhaustion RObservedSigner.
import RealOrder.
require import RObservedExhaustion.

lemma checked (O <: PrefixOracle {-RFailure}) :
  islossless O.hash => islossless O.derive =>
  equiv[ROnlyFailure(O).run ~ RObservedSigner(O).sign :
    ={arg,glob O} /\ !RFailure.bad{2} ==> res{1} = RFailure.bad{2}].
proof. exact (r_observed_failure_exact O). qed.
