(* Whole bounded nonce stream: public-history revisit accounting.
   Entry private-tail freshness is explicit; no external calls interleave. *)
require import AllCore List Distr FMap StdOrder StdBigop.
require import C10RawOracle C10RawGrind C10Counter C10HashDomains.
require import PrefixGuess PrefixHybrid RawTrial RTailFresh RoleGrind.
import RealOrder Bigreal BRA.
require FelTactic.

module Stream = {
  var i : int
  var bad : bool
  var random, message, seed, root : raw_input
  proc init(random0 message0 seed0 root0 : raw_input) : unit = {
    i <- 0; bad <- false;
    random <- random0; message <- message0; seed <- seed0; root <- root0;
  }
  proc next() : raw_input * digest = {
    var out;
    out <- witness;
    if (i < signing_budget) {
      out <@ Trial.run(r_query random message i,seed,root,message);
      bad <- bad \/ Trial.known;
      i <- i+1;
    }
    return out;
  }
}.
module StreamGrind = {
  proc run(random message seed root : raw_input) : (raw_input * digest) option = {
    var out, result;
    Stream.init(random,message,seed,root);
    result <- None;
    while (Stream.i < signing_budget /\ result = None) {
      out <@ Stream.next();
      if (accept_digest out.`2) { result <- Some out; }
    }
    return result;
  }
}.

op stream_invariant q0 i (seed root random message : raw_input) secret raw queries =
  0 <= i <= signing_budget /\ size seed = 32 /\ size root = 32 /\
  future_fresh secret random message i /\ history_recorded raw queries /\
  size queries = q0 + i.

lemma hash_accounted k :
  hoare[Independent.hash : history_recorded Independent.rawhistory Independent.queries /\
    size Independent.queries = k ==>
    history_recorded Independent.rawhistory Independent.queries /\
    size Independent.queries = k+1].
proof.
  proc; sp 1; if; auto; rewrite /history_recorded; smt(mem_rcons FMap.mem_set size_rcons).
qed.

lemma trial_step random message i q0 :
  hoare[Trial.run : 0 <= i < signing_budget /\ tail = r_query random message i /\
    future_fresh Independent.secrethistory random message i /\
    history_recorded Independent.rawhistory Independent.queries /\ size Independent.queries = q0+i ==>
    future_fresh Independent.secrethistory random message (i+1) /\
    history_recorded Independent.rawhistory Independent.queries /\ size Independent.queries = q0+i+1].
proof.
  proc; call (hash_accounted (q0+i)); wp.
  call (derive_future_fresh random message i); auto.
qed.

lemma stream_step q0 k :
  hoare[Stream.next : Stream.i = k /\
    stream_invariant q0 Stream.i Stream.seed Stream.root Stream.random Stream.message
      Independent.secrethistory Independent.rawhistory Independent.queries ==>
    Stream.i = (if k < signing_budget then k+1 else k) /\
    stream_invariant q0 Stream.i Stream.seed Stream.root Stream.random Stream.message
      Independent.secrethistory Independent.rawhistory Independent.queries].
proof.
  proc; sp 1; if.
  + exists* Stream.random,Stream.message; elim* => rand0 msg0.
    wp; call (trial_step rand0 msg0 k q0); auto; rewrite /stream_invariant; smt().
  by auto; smt().
qed.

lemma stream_bad_step q0 k :
  phoare[Stream.next : Stream.i = k /\ Stream.i < signing_budget /\ !Stream.bad /\
    stream_invariant q0 Stream.i Stream.seed Stream.root Stream.random Stream.message
      Independent.secrethistory Independent.rawhistory Independent.queries ==>
    Stream.bad] <= ((q0+k)%r * (1%r/2%r)^128).
proof.
  proc; rcondt 2; first by auto.
  exists* Independent.queries; elim* => qs.
  conseq (_ : _ : <= ((size qs)%r * (1%r/2%r)^128)); first by rewrite /stream_invariant; smt().
  wp; call (trial_cached_bound qs); auto; rewrite /stream_invariant; smt(future_fresh_current).
qed.

lemma stream_refines_grind :
  equiv[RoleGrind(Independent).run ~ StreamGrind.run :
    ={random,message,seed,root,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; while (i{1} = Stream.i{2} /\ ={result,glob Independent} /\
    random{1} = Stream.random{2} /\ message{1} = Stream.message{2} /\
    seed{1} = Stream.seed{2} /\ root{1} = Stream.root{2}).
  + inline Stream.next; rcondt{2} 2; first by auto.
    inline Trial.run; wp.
    call (_ : ={x,glob Independent} ==> ={res,glob Independent}).
    - by sim.
    wp; call (_ : ={tail,glob Independent} ==> ={res,glob Independent}).
    - by sim.
    by auto; rewrite /r_query.
  by inline Stream.init; auto.
qed.

lemma stream_cached_bound q0 random0 message0 seed0 root0 &m :
  0 <= q0 => size Independent.queries{m} = q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  future_fresh Independent.secrethistory{m} random0 message0 0 =>
  size seed0 = 32 => size root0 = 32 =>
  Pr[StreamGrind.run(random0,message0,seed0,root0) @ &m : Stream.bad]
    <= bigi predT (fun i => (q0+i)%r * (1%r/2%r)^128) 0 signing_budget.
proof.
  move=> hq hsize hrecord hf hs hr.
  fel 2 Stream.i (fun i => (q0+i)%r * (1%r/2%r)^128) signing_budget Stream.bad
    [Stream.next : (Stream.i < signing_budget)]
    (stream_invariant q0 Stream.i Stream.seed Stream.root Stream.random Stream.message
      Independent.secrethistory Independent.rawhistory Independent.queries) => //.
  + by rewrite /stream_invariant; smt().
  + by inline Stream.init; auto; rewrite /stream_invariant /signing_budget; smt().
  + exists* Stream.i; elim* => k; conseq (stream_bad_step q0 k); smt().
  + move=> c; conseq (stream_step q0 c); smt().
  move=> b c; proc; rcondf 2; by auto.
qed.
