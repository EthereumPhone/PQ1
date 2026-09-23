(* Preparation may compute the public root through the same secret and raw
   hash interfaces before the actual bounded R/H_msg loop. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Counter C10RawGrind.
require import PrefixGuess PrefixHybrid RoleGrind RoleGrindCost KeygenPrefixes.

module PreparedContext (P : Preparation) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ P(PreparationView(O)).run();
    result <@ RoleGrind(O).run(inputs.`1,inputs.`2,inputs.`3,inputs.`4);
    return result = None;
  }
}.

lemma preparation_view_lossless (O <: PrefixOracle) :
  islossless O.hash => islossless O.derive =>
  islossless PreparationView(O).hash /\
  islossless PreparationView(O).wots /\ islossless PreparationView(O).fors.
proof.
  move=> hh hd; split; first exact hh.
  split; proc; call hd; auto.
qed.

lemma prepared_lossless (P <: Preparation) (O <: PrefixOracle {-P}) :
  (forall (V <: PreparationOracle {-P}), islossless V.hash =>
    islossless V.wots => islossless V.fors => islossless P(V).run) =>
  islossless O.hash => islossless O.derive => islossless PreparedContext(P,O).run.
proof.
  move=> hp hh hd; have [#] hvh hvw hvf := preparation_view_lossless O hh hd.
  proc; call (role_grind_lossless O hh hd).
  call (hp (PreparationView(O)) hvh hvw hvf); auto.
qed.

lemma prepared_public_cost (P <: Preparation {-Independent}) q :
  hoare[P(PreparationView(Independent)).run : Independent.queries = [] ==>
    size Independent.queries <= q] =>
  hoare[PreparedContext(P,Independent).run : Independent.queries = [] ==>
    size Independent.queries <= q + signing_budget].
proof.
  move=> hp; proc; seq 1 : (size Independent.queries <= q); first by call hp; auto.
  exists* (size Independent.queries); elim* => q0.
  call (role_grind_public_cost q0); auto; smt().
qed.
