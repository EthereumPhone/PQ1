(* Bounded adaptive R/H_msg service. Limits count the whole session. This
   models grinding availability; it does not issue complete signatures. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter PrefixGuess RoleGrind RoleGrindCost.

module type RClientOracle = {
  proc hash(x : raw_input) : digest
  proc sign(random message : raw_input) : (raw_input * digest) option
}.
module type RClient (O : RClientOracle) = {
  proc run(seed root : raw_input) : unit { O.hash, O.sign }
}.

module RSession (O : PrefixOracle) = {
  var seed, root : raw_input
  var raw_limit, sign_limit, raw_calls, sign_calls : int
  var contexts : (raw_input * raw_input) list
  var bad : bool
  proc init(ps pk : raw_input, qraw qsign : int) : unit = {
    seed <- ps; root <- pk;
    raw_limit <- qraw; sign_limit <- qsign;
    raw_calls <- 0; sign_calls <- 0; contexts <- []; bad <- false;
  }
  proc hash(x : raw_input) : digest = {
    var result;
    result <- nseq 256 false;
    if (raw_calls < raw_limit) {
      result <@ O.hash(x); raw_calls <- raw_calls+1;
    }
    return result;
  }
  proc sign(random message : raw_input) : (raw_input * digest) option = {
    var result;
    result <- None;
    if (size message = 32 /\ (size random = 0 \/ size random = 16) /\ sign_calls < sign_limit) {
      result <@ RoleGrind(O).run(random,message,seed,root);
      bad <- bad \/ result = None;
      contexts <- rcons contexts (random,message);
      sign_calls <- sign_calls+1;
    }
    return result;
  }
}.

lemma session_hash_lossless (O <: PrefixOracle) :
  islossless O.hash => islossless RSession(O).hash.
proof. move=> hh; proc; sp 1; if; last by auto. wp; call hh; auto. qed.
lemma session_sign_lossless (O <: PrefixOracle) :
  islossless O.hash => islossless O.derive => islossless RSession(O).sign.
proof.
  move=> hh hd; proc; sp 1; if; last by auto.
  wp; call (role_grind_lossless O hh hd); auto.
qed.

lemma session_hash_cost q0 :
  hoare[RSession(Independent).hash :
    0 <= RSession.raw_calls <= RSession.raw_limit /\
    size Independent.queries <= q0+RSession.raw_calls ==>
    0 <= RSession.raw_calls <= RSession.raw_limit /\
    size Independent.queries <= q0+RSession.raw_calls].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* (size Independent.queries); elim* => q.
  call (independent_hash_count q); auto; smt().
qed.

lemma session_sign_cost q0 :
  hoare[RSession(Independent).sign :
    0 <= RSession.sign_calls <= RSession.sign_limit /\
    size Independent.queries <= q0+RSession.sign_calls*signing_budget ==>
    0 <= RSession.sign_calls <= RSession.sign_limit /\
    size Independent.queries <= q0+RSession.sign_calls*signing_budget].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* (size Independent.queries); elim* => q.
  call (role_grind_public_cost q); auto; smt().
qed.
