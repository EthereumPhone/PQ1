(* External Q2 research: a complete signature retains its context's first
   accepted digest, even after all FORS/WOTS/Merkle work. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid RoleGrind.
require import RawSigner GrindReturned SignerReturned.
require import GrindTrace GrindTraceRecorded GrindTraceReplay.

lemma finisher_keeps_trace (F <: SignatureFinisher {-Independent}) random0 message0 seed0 root0 answer :
  hoare[F(Independent).finish :
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer ==>
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer].
proof.
  proc (completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer) => //.
  + exact (hash_keeps_trace random0 message0 seed0 root0 answer).
  exact (derive_keeps_trace random0 message0 seed0 root0 answer).
qed.

lemma finish_trace_randomizer random0 message0 seed0 root0 (answer : raw_input * digest) :
  hoare[RawSigner(Independent).finish :
    randomizer = answer.`1 /\
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer ==>
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer /\
    (res <> None => (oget res).`1 = answer.`1)].
proof.
  conseq (finish_randomizer Independent answer.`1)
    (finisher_keeps_trace RawSigner random0 message0 seed0 root0 answer); smt().
qed.

op signature_trace s h random message seed root (signed : raw_signature option) =
  signed <> None => exists d,
    completed_trace s h random message seed root ((oget signed).`1,d).

lemma signer_records_trace random0 message0 seed0 root0 :
  hoare[RawSigner(Independent).sign :
    random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 ==>
    signature_trace Independent.secrethistory Independent.rawhistory
      random0 message0 seed0 root0 res].
proof.
  proc; seq 1 : (random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    (accepted <> None => completed_trace Independent.secrethistory Independent.rawhistory
      random0 message0 seed0 root0 (oget accepted))).
  + call (role_grind_records_trace random0 message0 seed0 root0); auto.
  sp 1; if; last by auto; rewrite /signature_trace.
  exists* accepted; elim* => answer.
  call (finish_trace_randomizer random0 message0 seed0 root0 (oget answer)).
  auto; rewrite /signature_trace; smt().
qed.

module type CompleteSigner (O : PrefixOracle) = {
  proc sign(seed root random message shuffle : raw_input) : raw_signature option { O.hash, O.derive }
}.

lemma complete_signer_keeps_trace (S <: CompleteSigner {-Independent}) random0 message0 seed0 root0 answer :
  hoare[S(Independent).sign :
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer ==>
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer].
proof.
  proc (completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer) => //.
  + exact (hash_keeps_trace random0 message0 seed0 root0 answer).
  exact (derive_keeps_trace random0 message0 seed0 root0 answer).
qed.

lemma completed_trace_entry s h random message seed root answer :
  completed_trace s h random message seed root answer =>
  h.[hmsg_input seed root (answer.`1 ++ nseq 16 0) message] = Some answer.`2.
proof.
  rewrite /completed_trace => hex.
  elim hex => j [#] hj hb hp ht ha he.
  move: ht he; rewrite /trial_recorded /trial_input /trial_digest; smt(domE).
qed.

lemma signer_repeated_digest random0 message0 seed0 root0 answer :
  hoare[RawSigner(Independent).sign :
    random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer ==>
    res <> None =>
      (oget res).`1 = answer.`1 /\
      Independent.rawhistory.[hmsg_input seed0 root0
        ((oget res).`1 ++ nseq 16 0) message0] = Some answer.`2].
proof.
  conseq (signer_records_trace random0 message0 seed0 root0)
    (complete_signer_keeps_trace RawSigner random0 message0 seed0 root0 answer);
    rewrite /signature_trace; smt(completed_trace_unique completed_trace_entry).
qed.
