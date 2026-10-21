(* First nonce exhaustion in a complete adaptive signing session. The public
   query allowance includes WOTS/FORS work and every failed signing attempt. *)
require import AllCore List Distr FMap StdOrder StdBigop.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RoleGrindCost RawTrial RTailFresh ClassifiedHistory.
require import RawSigner FullSession RObservedSigner RObservedHistory RObservedExhaustion.
require import FullRSession FullRHistory GrindExhaustion.
import RealOrder Bigreal BRA.

op full_r_sign_cost = 3*signing_budget+364892.
op full_r_valid (random message shuffle : raw_input) =
  size message = 32 /\ (size random = 0 \/ size random = 16) /\ size shuffle = 32.
op full_r_invariant q0 qr qs rc sc seed root failed bad secret raw queries =
  0 <= rc <= qr /\ 0 <= sc <= qs /\ size seed = 32 /\ size root = 32 /\
  size queries <= q0+rc+sc*full_r_sign_cost /\
  full_r_history secret raw queries seed root failed bad.

lemma full_r_bad_step q0 qr qs :
  phoare[FullRSession(Independent).sign :
    FullSession.raw_limit = qr /\ FullSession.sign_limit = qs /\
    !RFailure.bad /\ !FullSession.failed /\ full_r_valid random message shuffle /\
    FullSession.sign_calls < qs /\
    full_r_invariant q0 qr qs FullSession.raw_calls FullSession.sign_calls
      FullSession.seed FullSession.root FullSession.failed RFailure.bad
      Independent.secrethistory Independent.rawhistory Independent.queries ==>
    RFailure.bad] <= (exhaustion_charge (q0+qr+qs*full_r_sign_cost)).
proof.
  proc; rcondt 2; first by auto; rewrite /full_r_valid; smt().
  wp; call (r_observed_classified_exhaustion (q0+qr+qs*full_r_sign_cost)).
  auto; rewrite /full_r_invariant /full_r_history /full_r_valid /full_r_sign_cost /signing_budget; smt().
qed.

lemma full_r_sign_progress q0 qr qs c :
  hoare[FullRSession(Independent).sign :
    FullSession.raw_limit = qr /\ FullSession.sign_limit = qs /\ FullSession.sign_calls = c /\
    !FullSession.failed /\ full_r_valid random message shuffle /\ FullSession.sign_calls < qs /\
    full_r_invariant q0 qr qs FullSession.raw_calls FullSession.sign_calls
      FullSession.seed FullSession.root FullSession.failed RFailure.bad
      Independent.secrethistory Independent.rawhistory Independent.queries ==>
    FullSession.raw_limit = qr /\ FullSession.sign_limit = qs /\ FullSession.sign_calls = c+1 /\
    full_r_invariant q0 qr qs FullSession.raw_calls FullSession.sign_calls
      FullSession.seed FullSession.root FullSession.failed RFailure.bad
      Independent.secrethistory Independent.rawhistory Independent.queries].
proof.
  have hcost : hoare[FullRSession(Independent).sign :
    FullSession.raw_limit = qr /\ FullSession.sign_limit = qs /\ FullSession.sign_calls = c /\
    !FullSession.failed /\ full_r_valid random message shuffle /\ FullSession.sign_calls < qs /\
    0 <= FullSession.raw_calls <= qr /\ 0 <= FullSession.sign_calls <= qs /\
    size FullSession.seed = 32 /\ size FullSession.root = 32 /\
    size Independent.queries <= q0+FullSession.raw_calls+FullSession.sign_calls*full_r_sign_cost ==>
    FullSession.raw_limit = qr /\ FullSession.sign_limit = qs /\ FullSession.sign_calls = c+1 /\
    0 <= FullSession.raw_calls <= qr /\ 0 <= FullSession.sign_calls <= qs /\
    size FullSession.seed = 32 /\ size FullSession.root = 32 /\
    size Independent.queries <= q0+FullSession.raw_calls+FullSession.sign_calls*full_r_sign_cost].
  + proc; rcondt 2; first by auto; rewrite /full_r_valid; smt().
    wp; exists* Independent.queries; elim* => queries.
    call (r_observed_sign_public_cost (size queries)); auto; rewrite /full_r_sign_cost; smt().
  conseq hcost full_r_sign_history; rewrite /full_r_invariant; smt().
qed.

lemma full_r_hash_stable q0 qr qs c b :
  hoare[FullRSession(Independent).hash :
    FullSession.raw_limit = qr /\ FullSession.sign_limit = qs /\ FullSession.sign_calls = c /\ RFailure.bad = b /\
    full_r_invariant q0 qr qs FullSession.raw_calls FullSession.sign_calls
      FullSession.seed FullSession.root FullSession.failed RFailure.bad
      Independent.secrethistory Independent.rawhistory Independent.queries ==>
    FullSession.raw_limit = qr /\ FullSession.sign_limit = qs /\ FullSession.sign_calls = c /\ RFailure.bad = b /\
    full_r_invariant q0 qr qs FullSession.raw_calls FullSession.sign_calls
      FullSession.seed FullSession.root FullSession.failed RFailure.bad
      Independent.secrethistory Independent.rawhistory Independent.queries].
proof.
  have hcost : hoare[FullRSession(Independent).hash :
    FullSession.raw_limit = qr /\ FullSession.sign_limit = qs /\ FullSession.sign_calls = c /\ RFailure.bad = b /\
    0 <= FullSession.raw_calls <= qr /\ 0 <= FullSession.sign_calls <= qs /\
    size FullSession.seed = 32 /\ size FullSession.root = 32 /\
    size Independent.queries <= q0+FullSession.raw_calls+FullSession.sign_calls*full_r_sign_cost ==>
    FullSession.raw_limit = qr /\ FullSession.sign_limit = qs /\ FullSession.sign_calls = c /\ RFailure.bad = b /\
    0 <= FullSession.raw_calls <= qr /\ 0 <= FullSession.sign_calls <= qs /\
    size FullSession.seed = 32 /\ size FullSession.root = 32 /\
    size Independent.queries <= q0+FullSession.raw_calls+FullSession.sign_calls*full_r_sign_cost].
  + proc; sp 1; if; last by auto.
    wp; exists* Independent.queries; elim* => queries.
    call (independent_hash_count (size queries)); auto; smt().
  conseq hcost full_r_hash_history; rewrite /full_r_invariant; smt().
qed.

module FullRRun (A : FullClient) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged;
    FullRSession(Independent).init(seed,root,qr,qs);
    forged <@ A(FullRSession(Independent)).run(seed,root);
    return RFailure.bad;
  }
}.

lemma full_r_adaptive_exhaustion (A <: FullClient {-FullSession,-Independent,-RFailure})
    q0 qr qs seed root &m :
  0 <= q0 => 0 <= qr => 0 <= qs => size seed = 32 => size root = 32 =>
  size Independent.queries{m} <= q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  no_r_tails Independent.secrethistory{m} =>
  Pr[FullRRun(A).run(seed,root,qr,qs) @ &m : RFailure.bad] <=
    bigi predT (fun _ => exhaustion_charge (q0+qr+qs*full_r_sign_cost)) 0 qs.
proof.
  move=> hq hqr hqs hs hr hsize hrecord hnor.
  fel 1 FullSession.sign_calls (fun _ => exhaustion_charge (q0+qr+qs*full_r_sign_cost)) qs RFailure.bad
    [FullRSession(Independent).sign : (!FullSession.failed /\ full_r_valid random message shuffle /\
      FullSession.sign_calls < FullSession.sign_limit); FullRSession(Independent).hash : false]
    (FullSession.raw_limit = qr /\ FullSession.sign_limit = qs /\
      full_r_invariant q0 qr qs FullSession.raw_calls FullSession.sign_calls
        FullSession.seed FullSession.root FullSession.failed RFailure.bad
        Independent.secrethistory Independent.rawhistory Independent.queries) => //.
  + rewrite /full_r_invariant; smt().
  + inline FullRSession(Independent).init FullSession(Independent).init; auto;
      rewrite /full_r_invariant /full_r_history /=; smt(no_r_classified).
  + move=> b c; conseq (full_r_hash_stable q0 qr qs c b); smt().
  + conseq (full_r_bad_step q0 qr qs); smt().
  + move=> c; conseq (full_r_sign_progress q0 qr qs c); smt().
  move=> b c; proc; rcondf 2; by auto; rewrite /full_r_valid; smt().
qed.
