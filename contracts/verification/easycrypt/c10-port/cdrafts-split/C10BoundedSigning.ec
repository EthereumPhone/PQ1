(* Failure-aware WOTS signing and a guarded forgery game.
   None / bad denote no signature. Rust panics on exhaustion: this is a
   fail-stop abstraction of the experiment, not a recoverable firmware API.
   The existing total reductions remain conditional; this file does not
   establish a cryptographic probability for a real SHA-256 search. *)
require import AllCore List Distr.
require import SPHINCS_PLUS WOTS_C_Real WOTS_C_Scheme C10Counter C10BoundedGrind.
import FSSLXMTWES FSSLXMTWES.WTWES.

op prefix_hit (ps : pseed) (ad : adrs) (m : dgstblock) : bool =
  exists i, 0 <= i < signing_budget /\ hit ps ad m i.

op search_result (ps : pseed) (ad : adrs) (m : dgstblock) (r : int) : bool =
  (r = -1 <=> !prefix_hit ps ad m) /\
  (r <> -1 => 0 <= r < signing_budget /\ hit ps ad m r /\ grindC ps ad m = of_int r).

lemma search_contract (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock) :
  hoare[Search.run : ps = ps0 /\ ad = ad0 /\ m = m0 ==>
    search_result ps0 ad0 m0 res].
proof.
  conseq (search_spec ps0 ad0 m0); rewrite /search_result /prefix_hit;
    smt(first_hit_agrees).
qed.

module BoundedSign = {
  proc sign(sk : skWOTS * pseed * adrs, m : dgstblock) : (sigWOTS * cntr) option = {
    var r : int;
    var s : sigWOTS * cntr;
    var result : (sigWOTS * cntr) option;
    r <@ Search.run(sk.`2, sk.`3, m);
    result <- None;
    if (r <> -1) {
      s <@ WOTS_C_ES.sign(sk, m);
      result <- Some s;
    }
    return result;
  }
}.

lemma total_sign_counter (sk0 : skWOTS * pseed * adrs) (m0 : dgstblock) :
  hoare[WOTS_C_ES.sign : sk = sk0 /\ m = m0 ==>
    res.`2 = grindC sk0.`2 sk0.`3 m0].
proof.
  proc; while (counter = grindC sk0.`2 sk0.`3 m0); auto.
qed.

lemma bounded_sign_ll : islossless BoundedSign.sign.
proof.
  islossless.
  + by while true (len - size sig); auto; smt(size_rcons).
  by while true (signing_budget - i); auto; smt().
qed.

lemma bounded_sign_failure (sk0 : skWOTS * pseed * adrs) (m0 : dgstblock) :
  hoare[BoundedSign.sign : sk = sk0 /\ m = m0 ==>
    (res = None <=> !prefix_hit sk0.`2 sk0.`3 m0)].
proof.
  proc; seq 1 : (sk = sk0 /\ m = m0 /\ search_result sk0.`2 sk0.`3 m0 r).
  + by call (search_contract sk0.`2 sk0.`3 m0); auto.
  sp 1; if.
  + wp; call (_ : true ==> true); first by conseq WOTS_C_ES_sign_ll.
    auto; rewrite /search_result; smt().
  auto; rewrite /search_result; smt().
qed.

lemma bounded_sign_counter (sk0 : skWOTS * pseed * adrs) (m0 : dgstblock) :
  hoare[BoundedSign.sign : sk = sk0 /\ m = m0 ==>
    res <> None =>
      0 <= U32.val (oget res).`2 < signing_budget /\
      predC (ThC sk0.`2 sk0.`3 m0 (oget res).`2)].
proof.
  proc; seq 1 : (sk = sk0 /\ m = m0 /\ search_result sk0.`2 sk0.`3 m0 r).
  + by call (search_contract sk0.`2 sk0.`3 m0); auto.
  sp 1; if.
  + wp; call (total_sign_counter sk0 m0); auto => />.
    rewrite /search_result /hit => />.
    smt(of_int_value).
  by auto.
qed.

lemma search_contract_ph (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock) :
  phoare[Search.run : ps = ps0 /\ ad = ad0 /\ m = m0 ==>
    search_result ps0 ad0 m0 res] = 1%r.
proof. conseq search_ll (search_contract ps0 ad0 m0) => //. qed.

module TotalSign = {
  proc sign(sk : skWOTS * pseed * adrs, m : dgstblock) : sigWOTS * cntr = {
    var s : sigWOTS * cntr;
    s <@ WOTS_C_ES.sign(sk, m);
    return s;
  }
}.

(* Full signature agreement, not only counter agreement. The premise is a
   successful finite prefix for these arguments; it does not assert all
   real inputs have such a prefix. *)
lemma bounded_sign_agrees :
  equiv[BoundedSign.sign ~ TotalSign.sign :
    ={sk, m} /\ prefix_hit sk{1}.`2 sk{1}.`3 m{1} ==> res{1} = Some res{2}].
proof.
  proc; seq 1 0 : (={sk, m} /\ r{1} <> -1).
  + exists* sk{1}, m{1}; elim* => sk0 m0.
    call{1} (search_contract_ph sk0.`2 sk0.`3 m0).
    auto; rewrite /search_result; smt().
  sp 1 0; if{1}.
  + wp; call (_ : ={arg} ==> ={res}); first by sim.
    by auto.
  by call{2} WOTS_C_ES_sign_ll; auto.
qed.

(* The wrapper preserves the original adversary interface. Its dummy reply on
   failure is unobservable in the winning event: bad is absorbing and the game
   rejects that entire execution. Subsequent calls produce no signatures.
   As in the original games, admissible adversaries must not access the oracle
   globals directly; only the declared oracle interface is available. *)
module O_Bounded : Oracle_MEUFGCMA_WOTSC = {
  var bad : bool
  var ps : pseed
  proc init(ps_init : pseed) : unit = {
    ps <- ps_init; bad <- false;
    O_MEUFGCMA_WOTSC_Default.init(ps_init);
  }
  proc query(wad : wadrs, m : dgstblock) : pkWOTS * (sigWOTS * cntr) = {
    var r : int;
    var answer : pkWOTS * (sigWOTS * cntr);
    answer <- witness;
    if (!bad) {
      r <@ Search.run(ps, WAddress.val wad, m);
      if (r = -1) { bad <- true; }
      else { answer <@ O_MEUFGCMA_WOTSC_Default.query(wad, m); }
    }
    return answer;
  }
  proc get = O_MEUFGCMA_WOTSC_Default.get
  proc get_addresses = O_MEUFGCMA_WOTSC_Default.get_addresses
  proc nr_queries = O_MEUFGCMA_WOTSC_Default.nr_queries
  proc dist_addresses = O_MEUFGCMA_WOTSC_Default.dist_addresses
}.

lemma bounded_query_failure (ps0 : pseed) (wad0 : wadrs) (m0 : dgstblock) (bad0 : bool) :
  hoare[O_Bounded.query : O_Bounded.ps = ps0 /\ wad = wad0 /\ m = m0 /\ O_Bounded.bad = bad0 ==>
    O_Bounded.bad = (bad0 \/ !prefix_hit ps0 (WAddress.val wad0) m0)].
proof.
  proc; sp 1; if.
  + seq 1 : (O_Bounded.ps = ps0 /\ wad = wad0 /\ m = m0 /\ O_Bounded.bad = bad0 /\ !bad0 /\
      search_result ps0 (WAddress.val wad0) m0 r).
    - by call (search_contract ps0 (WAddress.val wad0) m0); auto.
    if.
    - auto; rewrite /search_result; smt().
    call (_ : true ==> true); first by conseq O_MEUFGCMA_WOTSC_query_ll.
    auto; rewrite /search_result; smt().
  by auto; smt().
qed.

module TotalOracle = {
  proc query(wad : wadrs, m : dgstblock) : pkWOTS * (sigWOTS * cntr) = {
    var answer : pkWOTS * (sigWOTS * cntr);
    answer <@ O_MEUFGCMA_WOTSC_Default.query(wad, m);
    return answer;
  }
}.

lemma bounded_query_agrees :
  equiv[O_Bounded.query ~ TotalOracle.query :
    ={wad, m, glob O_MEUFGCMA_WOTSC_Default} /\ !O_Bounded.bad{1} /\
    O_Bounded.ps{1} = O_MEUFGCMA_WOTSC_Default.ps{2} /\
    prefix_hit O_Bounded.ps{1} (WAddress.val wad{1}) m{1} ==>
    ={res, glob O_MEUFGCMA_WOTSC_Default} /\ !O_Bounded.bad{1}].
proof.
  proc; sp 1 0; if{1}.
  + seq 1 0 : (={wad, m, glob O_MEUFGCMA_WOTSC_Default} /\ !O_Bounded.bad{1} /\ r{1} <> -1).
    - exists* O_Bounded.ps{1}, wad{1}, m{1}; elim* => ps0 wad0 m0.
      call{1} (search_contract_ph ps0 (WAddress.val wad0) m0).
      auto; rewrite /search_result; smt().
    if{1}.
    - by wp; call{2} O_MEUFGCMA_WOTSC_query_ll; auto; smt().
    call (_ : ={arg, glob O_MEUFGCMA_WOTSC_Default} ==>
              ={res, glob O_MEUFGCMA_WOTSC_Default}); first by sim.
    by auto.
  by call{2} O_MEUFGCMA_WOTSC_query_ll; auto; smt().
qed.

module BoundedGame(A : Adv_MEUFGCMA_WOTSC) = {
  module G = M_EUF_GCMA_WOTSC_NPRF(A, O_Bounded, FC.O_THFC_Default)
  proc main() : bool = {
    var win : bool;
    win <@ G.main();
    return win /\ !O_Bounded.bad;
  }
}.

lemma failure_never_wins (A <: Adv_MEUFGCMA_WOTSC {-O_Bounded, -O_MEUFGCMA_WOTSC_Default}) :
  hoare[BoundedGame(A).main : true ==> O_Bounded.bad => !res].
proof.
  by proc; wp; conseq (_ : true ==> true); auto; smt().
qed.
