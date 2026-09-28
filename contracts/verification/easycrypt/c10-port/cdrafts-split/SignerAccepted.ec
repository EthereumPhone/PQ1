(* External Q research: private accepted-digest observation of actual complete
   signing. A failed complete signature contributes no success event. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10RawGrind C10HashDomains C10Randomizer.
require import PrefixGuess PrefixHybrid RoleGrind RawSigner.
require import RawTrial RTailFresh StreamBound GrindExhaustion AcceptedSampling StreamAccepted.
import RealOrder.

module SignObservation = {
  var accepted : (raw_input * digest) option
}.
module ObservedSigner (O : PrefixOracle) = {
  proc sign(seed root random message shuffle : raw_input) : raw_signature option = {
    var result;
    SignObservation.accepted <@ RoleGrind(O).run(random,message,seed,root);
    result <- None;
    if (SignObservation.accepted <> None) {
      result <@ RawSigner(O).finish(seed,(oget SignObservation.accepted).`1,
        (oget SignObservation.accepted).`2,shuffle);
    }
    return result;
  }
}.

lemma observed_signer_refines (O <: PrefixOracle {-SignObservation}) :
  equiv[RawSigner(O).sign ~ ObservedSigner(O).sign :
    ={seed,root,random,message,shuffle,glob O} ==> ={res,glob O}].
proof. by proc; sim. qed.

module ObservedSignEvent = {
  proc run(p : digest -> bool, seed root random message shuffle : raw_input) : bool = {
    var signed;
    signed <@ ObservedSigner(Independent).sign(seed,root,random,message,shuffle);
    return signed <> None /\ p (oget SignObservation.accepted).`2;
  }
}.
module GrindEvent = {
  proc run(p : digest -> bool, seed root random message : raw_input) : bool = {
    var accepted;
    accepted <@ RoleGrind(Independent).run(random,message,seed,root);
    return accepted <> None /\ p (oget accepted).`2;
  }
}.

lemma complete_sign_event_reduction :
  equiv[ObservedSignEvent.run ~ GrindEvent.run :
    ={p,seed,root,random,message,glob Independent} ==> res{1} => res{2}].
proof.
  proc; inline ObservedSigner(Independent).sign; sp 5 0.
  seq 1 1 : (={p,seed,root,random,message,glob Independent} /\
    SignObservation.accepted{1} = accepted{2}).
  + call (_ : ={random,message,seed,root,glob Independent} ==> ={res,glob Independent}).
    - by proc; sim.
    auto.
  sp 1 0; if{1}; last by auto.
  wp; call{1} (signer_finish_lossless Independent independent_hash_ll independent_derive_ll).
  auto.
qed.

lemma grind_accepted_ph p q0 : 0 <= q0 =>
  phoare[RoleGrind(Independent).run :
    size Independent.queries = q0 /\
    history_recorded Independent.rawhistory Independent.queries /\
    future_fresh Independent.secrethistory random message 0 /\
    size seed = 32 /\ size root = 32 ==>
    res <> None /\ p (oget res).`2] <= (accepted_probability p + revisit_charge q0).
proof.
  move=> hq; bypr => &m [#] hsize hrecord hf hs hr.
  exact (role_grind_accepted_bound p q0 random{m} message{m} seed{m} root{m} &m
    hq hsize hrecord hf hs hr).
qed.

lemma complete_sign_accepted_bound p0 q0 seed0 root0 random0 message0 shuffle0 &m :
  0 <= q0 => size Independent.queries{m} = q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  future_fresh Independent.secrethistory{m} random0 message0 0 =>
  size seed0 = 32 => size root0 = 32 =>
  Pr[ObservedSignEvent.run(p0,seed0,root0,random0,message0,shuffle0) @ &m : res] <=
    accepted_probability p0 + revisit_charge q0.
proof.
  move=> hq hsize hrecord hf hs hr.
  have hle :
    Pr[ObservedSignEvent.run(p0,seed0,root0,random0,message0,shuffle0) @ &m : res] <=
    Pr[GrindEvent.run(p0,seed0,root0,random0,message0) @ &m : res]
    by byequiv complete_sign_event_reduction => //.
  have hg : Pr[GrindEvent.run(p0,seed0,root0,random0,message0) @ &m : res] <=
    accepted_probability p0 + revisit_charge q0.
  + byphoare (_ : p = p0 /\
      size Independent.queries = q0 /\
      history_recorded Independent.rawhistory Independent.queries /\
      future_fresh Independent.secrethistory random message 0 /\
      size seed = 32 /\ size root = 32 ==> res) => //.
    proc; call (grind_accepted_ph p0 q0 hq); auto.
  apply (ler_trans (Pr[GrindEvent.run(p0,seed0,root0,random0,message0) @ &m : res])).
  + exact hle.
  exact hg.
qed.
