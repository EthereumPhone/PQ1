(* Raw shared-table loop after adaptive preparation under the same secret. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Bytes C10Counter C10Randomizer.
require import PrefixGuess PrefixHybrid PrefixGames RoleGrind KeygenPrefixes PreparedGrind PreparedExhaustion GrindExhaustion.

module PreparedRawGame (P : Preparation) = {
  proc run() : bool = {
    var key, inputs, result;
    key <$ full_digest;
    Physical.key <- bits_to_bytes key;
    Shared.init();
    inputs <@ P(PreparationView(Physical)).run();
    result <@ StatefulGrind(Shared).run(bits_to_bytes key,
      inputs.`1,inputs.`2,inputs.`3,inputs.`4);
    return result = None;
  }
}.

lemma prepared_raw_refinement (P <: Preparation {-Physical,-Shared}) :
  equiv[PreparedRawGame(P).run ~ RealGame(PreparedContext(P)).run :
    ={glob P} ==> ={res,glob P,glob Shared}].
proof.
  proc; inline PreparedContext(P,Physical).run.
  seq 3 3 : (={glob P,glob Shared,glob Physical} /\
    Physical.key{1} = bits_to_bytes key{1}).
  + inline Shared.init; auto.
  wp; call grind_refinement.
  call (_ : ={glob P,glob Shared,glob Physical} ==> ={res,glob P,glob Shared,glob Physical}).
  + by sim.
  auto.
qed.

lemma prepared_raw_exhaustion
  (P <: Preparation {-Physical,-Hybrid,-Shared,-Independent}) q &m :
  (forall (V <: PreparationOracle {-P}), islossless V.hash =>
    islossless V.wots => islossless V.fors => islossless P(V).run) =>
  0 <= q =>
  hoare[P(PreparationView(Independent)).run : Independent.queries = [] ==>
    size Independent.queries <= q /\ size res.`3 = 32 /\ size res.`4 = 32] =>
  Pr[PreparedRawGame(P).run() @ &m : res] <=
    exhaustion_charge q + (q+signing_budget)%r * (1%r/2%r)^256.
proof.
  move=> hll hq hp.
  have he : Pr[PreparedRawGame(P).run() @ &m : res] =
    Pr[RealGame(PreparedContext(P)).run() @ &m : res]
    by byequiv (prepared_raw_refinement P) => //.
  rewrite he; exact (prepared_physical_exhaustion P q &m hll hq hp).
qed.
