(* External Q research: one fixed hypertree target for the actual memoized grind.
   The explicit entry-freshness and prior-history premises are essential. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10RawGrind C10Randomizer.
require import PrefixGuess RawTrial RTailFresh RoleGrind StreamBound GrindExhaustion.
require import AcceptedSampling AcceptedHypertree StreamAccepted.
import RealOrder.

lemma role_grind_ht_bound target q0 random message seed root &m :
  size target = 18 =>
  0 <= q0 => size Independent.queries{m} = q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  future_fresh Independent.secrethistory{m} random message 0 =>
  size seed = 32 => size root = 32 =>
  Pr[RoleGrind(Independent).run(random,message,seed,root) @ &m :
    res <> None /\ take 18 (drop 143 (oget res).`2) = target]
    <= (1%r/2%r)^18 + revisit_charge q0.
proof.
  move=> ht hq hsize hrecord hf hs hr.
  have h := role_grind_accepted_bound
    (fun d => take 18 (drop 143 d) = target) q0 random message seed root &m
    hq hsize hrecord hf hs hr.
  by rewrite (accepted_ht_probability target ht) in h.
qed.
