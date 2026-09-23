(* One adaptive call: a new context is fresh; an accepted old context replays.
   The caller must preserve accepted contexts until the first failure. *)
require import AllCore List Distr FMap StdOrder StdBigop.
require import C10RawOracle C10RawGrind C10Counter.
require import PrefixGuess PrefixHybrid RoleGrind RawTrial RTailFresh RTailContexts.
require import GrindTail GrindExhaustion ExhaustionCharges IdealWitness.
import RealOrder Bigreal BRA.

op accepted_contexts (secret raw : (raw_input,digest) fmap)
  (contexts : (raw_input * raw_input) list) seed root =
  forall random message, (random,message) \in contexts =>
    ideal_witness secret raw random message seed root.

lemma exhaustion_nonnegative q : 0 <= q => 0%r <= exhaustion_charge q.
proof.
  move=> hq; rewrite /exhaustion_charge; apply addr_ge0.
  + apply expr_ge0; have hp := reject_positive; smt().
  rewrite /revisit_charge; apply Bigreal.sumr_ge0_seq => i.
  rewrite mem_range => hi _; apply mulr_ge0.
  + rewrite le_fromint; smt().
  apply expr_ge0; smt().
qed.

lemma context_exhaustion q (contexts : (raw_input * raw_input) list) :
  phoare[RoleGrind(Independent).run :
    size Independent.queries <= q /\
    history_recorded Independent.rawhistory Independent.queries /\
    r_history_contexts Independent.secrethistory contexts /\
    accepted_contexts Independent.secrethistory Independent.rawhistory contexts seed root /\
    size message = 32 /\ size seed = 32 /\ size root = 32 ==>
    res = None] <= (exhaustion_charge q).
proof.
  bypr => &m [#] hq hrecord hcontexts haccept hm hs hr.
  have hq0 : 0 <= q by smt(size_ge0).
  case (List.mem contexts (random{m},message{m})) => hmem.
  + have hw : ideal_witness Independent.secrethistory{m} Independent.rawhistory{m}
      random{m} message{m} seed{m} root{m}
      by apply haccept; exact hmem.
    rewrite (ideal_witness_failure_zero random{m} message{m} seed{m} root{m} &m hw).
    exact (exhaustion_nonnegative q hq0).
  have hf := unqueried_context_fresh Independent.secrethistory{m} contexts random{m} message{m}
    hcontexts hm hmem.
  have hh := role_grind_exhaustion_bound (size Independent.queries{m})
    random{m} message{m} seed{m} root{m} &m _ _ hrecord hf hs hr.
  + exact size_ge0.
  + by [].
  have hc := exhaustion_charge_mono (size Independent.queries{m}) q hq.
  smt().
qed.
