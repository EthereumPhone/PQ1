(* Adaptive preparation and a bounded grind through the same secret-keyed
   derivation interface. Width and cost premises must be proved by the caller. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Counter C10RawGrind.
require import PrefixGuess PrefixHybrid PrefixGames PrefixIdeal RawTrial RTailFresh.
require import RoleGrind RoleGrindCost KeygenPrefixes PreparedHistory PreparedGrind.
require import GrindExhaustion ExhaustionCharges.
import RealOrder.

lemma prepared_role_exhaustion q :
  phoare[RoleGrind(Independent).run :
    size Independent.queries <= q /\
    history_recorded Independent.rawhistory Independent.queries /\
    no_r_tails Independent.secrethistory /\ size seed = 32 /\ size root = 32 ==>
    res = None] <= (exhaustion_charge q).
proof.
  bypr => &m [#] hq hrecord hnor hs hr.
  have hf := no_r_future_fresh Independent.secrethistory{m} random{m} message{m} hnor.
  have h := role_grind_exhaustion_bound (size Independent.queries{m})
    random{m} message{m} seed{m} root{m} &m _ _ hrecord hf hs hr.
  + exact size_ge0.
  + by [].
  have hm := exhaustion_charge_mono (size Independent.queries{m}) q hq.
  smt().
qed.

lemma prepared_independent_exhaustion (P <: Preparation {-Independent}) q :
  hoare[P(PreparationView(Independent)).run : Independent.queries = [] ==>
    size Independent.queries <= q /\ size res.`3 = 32 /\ size res.`4 = 32] =>
  phoare[IndependentGame(PreparedContext(P)).run : true ==> res] <= (exhaustion_charge q).
proof.
  move=> hp.
  have hp' : hoare[P(PreparationView(Independent)).run :
    Independent.queries = [] /\ no_r_tails Independent.secrethistory /\
    history_recorded Independent.rawhistory Independent.queries ==>
    size Independent.queries <= q /\ size res.`3 = 32 /\ size res.`4 = 32 /\
    no_r_tails Independent.secrethistory /\
    history_recorded Independent.rawhistory Independent.queries].
  + conseq hp (preparation_preserves_history P); smt().
  proc; inline PreparedContext(P,Independent).run; wp.
  call (prepared_role_exhaustion q); call hp'; inline Independent.init; auto.
  rewrite /no_r_tails /history_recorded; smt(FMap.mem_empty).
qed.

lemma prepared_physical_exhaustion
  (P <: Preparation {-Physical,-Hybrid,-Shared,-Independent}) q &m :
  (forall (V <: PreparationOracle {-P}), islossless V.hash =>
    islossless V.wots => islossless V.fors => islossless P(V).run) =>
  0 <= q =>
  hoare[P(PreparationView(Independent)).run : Independent.queries = [] ==>
    size Independent.queries <= q /\ size res.`3 = 32 /\ size res.`4 = 32] =>
  Pr[RealGame(PreparedContext(P)).run() @ &m : res] <=
    exhaustion_charge q + (q + signing_budget)%r * (1%r/2%r)^256.
proof.
  move=> hll hq hp.
  have hcll : forall (O <: PrefixOracle {-PreparedContext(P)}),
    islossless O.hash => islossless O.derive => islossless PreparedContext(P,O).run.
  + move=> O hh hd; exact (prepared_lossless P O hll hh hd).
  have hcost : hoare[PreparedContext(P,Independent).run : Independent.queries = [] ==>
    size Independent.queries <= q + signing_budget].
  + apply (prepared_public_cost P q); conseq hp; smt().
  have hi : Pr[IndependentGame(PreparedContext(P)).run() @ &m : res] <= exhaustion_charge q
    by byphoare (prepared_independent_exhaustion P q hp) => //.
  have hh := physical_to_independent (PreparedContext(P)) (q+signing_budget) &m
    hcll _ hcost.
  + rewrite /signing_budget; smt().
  smt().
qed.
