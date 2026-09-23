(* Exhaustion of the actual independent-table stream, with all cached hits charged.
   Prior raw history is arbitrary; entry freshness of the private nonce tails is explicit. *)
require import AllCore List Distr FMap StdOrder StdBigop.
require import C10RawOracle C10Counter C10RawGrind C10Randomizer.
require import PrefixGuess RawTrial RTailFresh RoleGrind StreamBound GrindTail StreamExpectation.
import RealOrder Bigreal BRA.

op revisit_charge q0 =
  bigi predT (fun i => (q0+i)%r * (1%r/2%r)^128) 0 signing_budget.
op exhaustion_charge q0 = reject_mass^signing_budget + revisit_charge q0.

lemma stream_exhaustion_bound q0 random message seed root &m :
  0 <= q0 => size Independent.queries{m} = q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  future_fresh Independent.secrethistory{m} random message 0 =>
  size seed = 32 => size root = 32 =>
  Pr[StreamGrind.run(random,message,seed,root) @ &m : res = None]
    <= exhaustion_charge q0.
proof.
  move=> hq hsize hrecord hf hs hr.
  have hc := stream_cached_bound q0 random message seed root &m hq hsize hrecord hf hs hr.
  have ht := stream_no_revisit_tail random message seed root &m.
  have hsplit : Pr[StreamGrind.run(random,message,seed,root) @ &m : res = None]
    <= Pr[StreamGrind.run(random,message,seed,root) @ &m : Stream.bad]
      + Pr[StreamGrind.run(random,message,seed,root) @ &m : !Stream.bad /\ res = None].
  + rewrite Pr[mu_split Stream.bad] ler_add.
    - by rewrite Pr[mu_sub]; smt().
    by rewrite Pr[mu_sub]; smt().
  by rewrite /exhaustion_charge /revisit_charge; smt().
qed.

lemma role_grind_exhaustion_bound q0 random message seed root &m :
  0 <= q0 => size Independent.queries{m} = q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  future_fresh Independent.secrethistory{m} random message 0 =>
  size seed = 32 => size root = 32 =>
  Pr[RoleGrind(Independent).run(random,message,seed,root) @ &m : res = None]
    <= exhaustion_charge q0.
proof.
  move=> hq hsize hrecord hf hs hr.
  have he : Pr[RoleGrind(Independent).run(random,message,seed,root) @ &m : res = None] =
    Pr[StreamGrind.run(random,message,seed,root) @ &m : res = None]
    by byequiv stream_refines_grind => //.
  by rewrite he; apply (stream_exhaustion_bound q0 random message seed root &m).
qed.
