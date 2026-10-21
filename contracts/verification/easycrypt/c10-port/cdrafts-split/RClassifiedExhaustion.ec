(* Actual R grinding after complete signing work: every live context is
   either unused or has a retained successful trace. No fresh-history
   hypothesis is supplied separately by the caller. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid RoleGrind.
require import RawTrial GrindExhaustion ExhaustionCharges ContextExhaustion.
require import ClassifiedHistory GrindTraceReplay IdealWitness.
import RealOrder.

lemma classified_grind_exhaustion q :
  phoare[RoleGrind(Independent).run :
    size Independent.queries <= q /\
    history_recorded Independent.rawhistory Independent.queries /\
    classified_history Independent.secrethistory Independent.rawhistory seed root /\
    size message = 32 /\ size seed = 32 /\ size root = 32 ==>
    res = None] <= (exhaustion_charge q).
proof.
  bypr => &m [#] hq hrecord hclassified hm hs hr.
  have hq0 : 0 <= q by smt(size_ge0).
  have hc := hclassified random{m} message{m} hm.
  rewrite /classified_context in hc.
  case hc => hf.
  + have hb := role_grind_exhaustion_bound (size Independent.queries{m})
      random{m} message{m} seed{m} root{m} &m _ _ hrecord hf hs hr.
    - exact size_ge0.
    - by [].
    have he := exhaustion_charge_mono (size Independent.queries{m}) q hq.
    smt().
  elim hf => answer ht.
  have hw := completed_trace_witness Independent.secrethistory{m}
    Independent.rawhistory{m} random{m} message{m} seed{m} root{m} answer ht.
  rewrite (ideal_witness_failure_zero random{m} message{m} seed{m} root{m} &m hw).
  exact (exhaustion_nonnegative q hq0).
qed.
