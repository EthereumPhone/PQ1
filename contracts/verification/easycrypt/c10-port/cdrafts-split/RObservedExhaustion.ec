(* The observer's event is exactly actual R exhaustion, even though the full
   WOTS/FORS finisher runs after a successful nonce search. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RoleGrind RawSigner.
require import RawTrial ClassifiedHistory GrindExhaustion RClassifiedExhaustion RObservedSigner.
import RealOrder.

module ROnlyFailure (O : PrefixOracle) = {
  proc run(seed root random message shuffle : raw_input) : bool = {
    var accepted;
    accepted <@ RoleGrind(O).run(random,message,seed,root);
    return accepted = None;
  }
}.

lemma r_observed_failure_exact (O <: PrefixOracle {-RFailure}) :
  islossless O.hash => islossless O.derive =>
  equiv[ROnlyFailure(O).run ~ RObservedSigner(O).sign :
    ={arg,glob O} /\ !RFailure.bad{2} ==> res{1} = RFailure.bad{2}].
proof.
  move=> hh hd; proc; seq 1 1 : (={accepted} /\ !RFailure.bad{2}).
  + call (_ : ={glob O}); first by sim.
    auto.
  sp 0 2; if{2}.
  + by call{2} (signer_finish_lossless O hh hd); auto => />.
  by auto => />.
qed.

lemma r_only_classified_exhaustion q :
  phoare[ROnlyFailure(Independent).run :
    size Independent.queries <= q /\
    history_recorded Independent.rawhistory Independent.queries /\
    classified_history Independent.secrethistory Independent.rawhistory seed root /\
    size message = 32 /\ size seed = 32 /\ size root = 32 ==>
    res] <= (exhaustion_charge q).
proof. proc; call (classified_grind_exhaustion q); auto. qed.

lemma r_observed_classified_exhaustion q :
  phoare[RObservedSigner(Independent).sign :
    !RFailure.bad /\ size Independent.queries <= q /\
    history_recorded Independent.rawhistory Independent.queries /\
    classified_history Independent.secrethistory Independent.rawhistory seed root /\
    size message = 32 /\ size seed = 32 /\ size root = 32 ==>
    RFailure.bad] <= (exhaustion_charge q).
proof.
  bypr => &m [#] hb hq hrecord hclassified hm hs hr.
  have he : Pr[ROnlyFailure(Independent).run(seed{m},root{m},random{m},message{m},shuffle{m}) @ &m : res] =
    Pr[RObservedSigner(Independent).sign(seed{m},root{m},random{m},message{m},shuffle{m}) @ &m : RFailure.bad].
  + by byequiv (r_observed_failure_exact Independent independent_hash_ll independent_derive_ll) => //.
  rewrite -he; byphoare (r_only_classified_exhaustion q) => //.
qed.
