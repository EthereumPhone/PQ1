(* A private sticky observer of actual nonce-grinder exhaustion. The original
   grinder and complete finisher execute unchanged, including WOTS failure. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RoleGrind RoleGrindCost RawSigner.

module RFailure = { var bad : bool }.

module RObservedSigner (O : PrefixOracle) = {
  proc sign(seed root random message shuffle : raw_input) : raw_signature option = {
    var accepted, result;
    accepted <@ RoleGrind(O).run(random,message,seed,root);
    RFailure.bad <- RFailure.bad \/ accepted = None;
    result <- None;
    if (accepted <> None) {
      result <@ RawSigner(O).finish(seed,(oget accepted).`1,(oget accepted).`2,shuffle);
    }
    return result;
  }
}.

lemma r_observed_sign_erases (O <: PrefixOracle {-RFailure}) :
  equiv[RawSigner(O).sign ~ RObservedSigner(O).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof. by proc; sim. qed.

lemma r_observed_sign_lossless (O <: PrefixOracle {-RFailure}) :
  islossless O.hash => islossless O.derive => islossless RObservedSigner(O).sign.
proof.
  move=> hh hd; proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (role_grind_lossless O hh hd); auto.
  sp 2; if; auto; call (signer_finish_lossless O hh hd); auto.
qed.

lemma r_observed_sign_failure (O <: PrefixOracle {-RFailure}) b :
  hoare[RObservedSigner(O).sign : RFailure.bad = b ==>
    (b => RFailure.bad) /\ (RFailure.bad => b \/ res = None)].
proof.
  proc; seq 1 : (RFailure.bad = b).
  + call (_ : true ==> true); first by trivial.
    auto.
  sp 2; if; last by auto; smt().
  call (_ : true ==> true); first by trivial.
  auto; smt().
qed.
