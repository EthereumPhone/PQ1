(* The session invokes the concrete raw R/H_msg procedure, using the same
   Physical.key used to derive WOTS secrets during key generation. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Bytes C10Randomizer C10Counter.
require import PrefixGuess PrefixHybrid PrefixGames RoleGrind KeygenPrefixes KeygenExhaustion.
require import RSession SessionKeygen.

module RawSession = {
  proc hash = RSession(Physical).hash
  proc sign(random message : raw_input) : (raw_input * digest) option = {
    var result;
    result <- None;
    if (size message = 32 /\ (size random = 0 \/ size random = 16) /\ RSession.sign_calls < RSession.sign_limit) {
      result <@ StatefulGrind(Shared).run(Physical.key,random,message,RSession.seed,RSession.root);
      RSession.bad <- RSession.bad \/ result = None;
      RSession.contexts <- rcons RSession.contexts (random,message);
      RSession.sign_calls <- RSession.sign_calls+1;
    }
    return result;
  }
}.

lemma raw_sign_refinement :
  equiv[RawSession.sign ~ RSession(Physical).sign :
    ={random,message,glob Shared,glob Physical,glob RSession} ==>
    ={res,glob Shared,glob Physical,glob RSession}].
proof. proc; sp 1 1; if; auto; wp; call grind_refinement; auto. qed.

module RawSessionDriver (A : RClient) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    RSession(Physical).init(seed,root,qr,qs);
    A(RawSession).run(seed,root);
    return RSession.bad;
  }
}.

lemma raw_client_refinement (A <: RClient {-Shared,-Physical,-RSession}) :
  equiv[A(RawSession).run ~ A(RSession(Physical)).run :
    ={seed,root,glob A,glob Shared,glob Physical,glob RSession} ==>
    ={res,glob A,glob Shared,glob Physical,glob RSession}].
proof.
  proc (={glob Shared,glob Physical,glob RSession}) => //.
  + proc; sim.
  conseq raw_sign_refinement; smt().
qed.

lemma raw_driver_refinement (A <: RClient {-Shared,-Physical,-RSession}) :
  equiv[RawSessionDriver(A).run ~ SessionDriver(A,Physical).run :
    ={seed,root,qr,qs,glob A,glob Shared,glob Physical} ==>
    ={res,glob A,glob Shared,glob Physical,glob RSession}].
proof.
  proc; call (raw_client_refinement A); inline RSession(Physical).init; auto.
qed.

module RawSessionGame (A : RClient) = {
  proc run() : bool = {
    var key, inputs, result;
    key <$ full_digest;
    Physical.key <- bits_to_bytes key;
    Shared.init();
    inputs <@ KeygenPreparation(PreparationView(Physical)).run();
    result <@ RawSessionDriver(A).run(inputs.`3,inputs.`4,SessionLimits.raw_cap,SessionLimits.sign_cap);
    return result;
  }
}.

lemma raw_session_game_refinement (A <: RClient {-Shared,-Physical,-RSession}) :
  equiv[RawSessionGame(A).run ~ RealGame(SessionKeygenContext(A)).run :
    ={glob A,glob KeygenInputs,glob SessionLimits} ==>
    ={res,glob A,glob Shared,glob Physical,glob RSession}].
proof.
  proc; inline SessionKeygenContext(A,Physical).run; wp.
  call (raw_driver_refinement A).
  call (_ : ={glob Shared,glob Physical,glob KeygenInputs} ==>
    ={res,glob Shared,glob Physical,glob KeygenInputs}).
  + proc; sim.
  inline Shared.init; auto.
qed.
