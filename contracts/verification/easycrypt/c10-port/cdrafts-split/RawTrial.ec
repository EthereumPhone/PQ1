(* Fresh keyed derivation followed by an actual memoized H_msg query.
   This preserves arbitrary prior history and charges cached H_msg hits. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10RawGrind C10HashDomains C10Randomizer.
require import PrefixGuess PrefixHybrid RawRHistory.

op history_recorded (h : (raw_input,digest) fmap) (qs : raw_input list) =
  forall x, x \in h => x \in qs.

module Trial = {
  var known : bool
  proc run(tail seed root message : raw_input) : raw_input * digest = {
    var rd, hd, r, x;
    rd <@ Independent.derive(tail);
    r <- compact_r rd;
    x <- hmsg_input seed root (r ++ nseq 16 0) message;
    known <- x \in Independent.rawhistory;
    hd <@ Independent.hash(x);
    return (r,hd);
  }
}.

lemma trial_cached_bound qs :
  phoare[Trial.run :
    tail \notin Independent.secrethistory /\
    history_recorded Independent.rawhistory qs /\
    size seed = 32 /\ size root = 32 ==>
    Trial.known] <= ((size qs)%r * (1%r/2%r)^128).
proof.
  proc.
  seq 4 : Trial.known ((size qs)%r * (1%r/2%r)^128) 1%r 1%r 0%r => //.
  + wp; inline Independent.derive.
    rcondt 2; first by auto.
    wp; rnd; wp; skip => /> &m hnew hrecord hs hr.
    apply (RealOrder.ler_trans (mu full_digest (fun rd =>
      hmsg_input seed{m} root{m} (compact_r rd ++ nseq 16 0) message{m} \in qs))).
    - apply mu_le => rd _; rewrite /= FMap.get_set_sameE /=.
      exact (hrecord _).
    exact (fresh_derived_hmsg_prior_history seed{m} root{m} message{m} qs hs hr).
  by hoare; inline Independent.hash; sp 2; if; auto; smt().

qed.

lemma recorded_hash :
  hoare[Independent.hash : history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof.
  proc; sp 1; if; auto; rewrite /history_recorded; smt(mem_rcons mem_set).
qed.
lemma recorded_derive :
  hoare[Independent.derive : history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof. by proc; if; auto. qed.
