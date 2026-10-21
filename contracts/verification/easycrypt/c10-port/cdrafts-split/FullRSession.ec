(* The complete adaptive signing session with a private R-failure observer.
   All original state, admission checks and WOTS-failure behavior are kept. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawSigner FullSession RObservedSigner.

module FullRSession (O : PrefixOracle) = {
  proc init(ps pr : raw_input, qr qs : int) : unit = {
    FullSession(O).init(ps,pr,qr,qs);
    RFailure.bad <- false;
  }
  proc hash = FullSession(O).hash
  proc sign(random message shuffle : raw_input) : raw_signature option = {
    var result; result <- None;
    if (!FullSession.failed /\ size message = 32 /\
        (size random = 0 \/ size random = 16) /\ size shuffle = 32 /\
        FullSession.sign_calls < FullSession.sign_limit) {
      result <@ RObservedSigner(O).sign(FullSession.seed,FullSession.root,random,message,shuffle);
      FullSession.sign_calls <- FullSession.sign_calls+1;
      if (result <> None) {
        FullSession.signed_messages <- rcons FullSession.signed_messages message;
      } else { FullSession.failed <- true; }
    }
    return result;
  }
}.

lemma full_r_init_erases (O <: PrefixOracle {-FullSession,-RFailure}) :
  equiv[FullSession(O).init ~ FullRSession(O).init :
    ={arg,glob O} ==> ={res,glob FullSession,glob O}].
proof. by proc; inline FullSession(O).init; auto. qed.

lemma full_r_hash_erases (O <: PrefixOracle {-FullSession,-RFailure}) :
  equiv[FullSession(O).hash ~ FullRSession(O).hash :
    ={arg,glob FullSession,glob O} ==> ={res,glob FullSession,glob O}].
proof. by proc; sim. qed.

lemma full_r_sign_erases (O <: PrefixOracle {-FullSession,-RFailure}) :
  equiv[FullSession(O).sign ~ FullRSession(O).sign :
    ={arg,glob FullSession,glob O} ==> ={res,glob FullSession,glob O}].
proof.
  proc; sp 1 1; if; first by auto.
  + by wp; call (r_observed_sign_erases O); auto => />.
  by auto.
qed.

lemma full_r_sign_lossless (O <: PrefixOracle {-FullSession,-RFailure}) :
  islossless O.hash => islossless O.derive => islossless FullRSession(O).sign.
proof.
  move=> hh hd; proc; sp 1; if; auto;
    wp; call (r_observed_sign_lossless O hh hd); auto.
qed.

lemma full_r_sign_failure (O <: PrefixOracle {-FullSession,-RFailure}) :
  hoare[FullRSession(O).sign : RFailure.bad => FullSession.failed ==>
    RFailure.bad => FullSession.failed].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* RFailure.bad; elim* => b.
  call (r_observed_sign_failure O b); auto; smt().
qed.

lemma full_r_hash_failure (O <: PrefixOracle {-FullSession,-RFailure}) :
  hoare[FullRSession(O).hash : RFailure.bad => FullSession.failed ==>
    RFailure.bad => FullSession.failed].
proof.
  proc; sp 1; if; last by auto.
  wp; call (_ : true ==> true); first by trivial.
  auto.
qed.
