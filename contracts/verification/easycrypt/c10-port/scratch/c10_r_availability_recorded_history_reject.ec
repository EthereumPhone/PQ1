require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid RoleGrind.
require import RawTrial GrindExhaustion ExhaustionCharges ContextExhaustion.
require import ClassifiedHistory GrindTraceReplay IdealWitness.
import RealOrder.
require import RClassifiedExhaustion.

lemma checked q :
  phoare[RoleGrind(Independent).run :
    size Independent.queries <= q /\
    true /\
    classified_history Independent.secrethistory Independent.rawhistory seed root /\
    size message = 32 /\ size seed = 32 /\ size root = 32 ==>
    res = None] <= (exhaustion_charge q).
proof. exact (classified_grind_exhaustion q). qed.
