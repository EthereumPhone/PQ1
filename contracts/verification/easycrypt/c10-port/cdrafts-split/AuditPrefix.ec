(* External Q research. Observe public-prefix collisions without changing the
   independent game's public/private responses, history or query transcript. *)
require import AllCore List Distr FMap StdOrder StdBigop.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal PrefixAudit.
require FelTactic.
import RField RealOrder Bigreal BRA.

module AuditedIndependent = {
  var queries : raw_input list
  proc init(n q : int) : unit = {
    PrefixAudit.init(n,q);
    Independent.secrethistory <- empty; queries <- [];
  }
  proc hash(x : raw_input) : digest = {
    var result;
    queries <- rcons queries x;
    result <@ PrefixAudit.hash(x);
    return result;
  }
  proc derive(tail : raw_input) : digest = {
    var result;
    result <@ Independent.derive(tail);
    return result;
  }
}.
module AuditedGame (A : PrefixContext) = {
  proc run(n q : int) : bool = {
    var result;
    AuditedIndependent.init(n,q);
    result <@ A(AuditedIndependent).run();
    return result;
  }
}.

lemma audited_hash_observation :
  equiv[Independent.hash ~ AuditedIndependent.hash :
    ={x,Independent.secrethistory} /\
    Independent.rawhistory{1} = PrefixAudit.history{2} /\
    Independent.queries{1} = AuditedIndependent.queries{2} ==>
    ={res,Independent.secrethistory} /\
    Independent.rawhistory{1} = PrefixAudit.history{2} /\
    Independent.queries{1} = AuditedIndependent.queries{2}].
proof.
  by proc; inline PrefixAudit.hash; sp 1 3; if{2}; wp; if; auto.
qed.

lemma audited_context_observation
  (A <: PrefixContext {-Independent,-AuditedIndependent,-PrefixAudit}) :
  equiv[A(Independent).run ~ A(AuditedIndependent).run :
    ={glob A,Independent.secrethistory} /\
    Independent.rawhistory{1} = PrefixAudit.history{2} /\
    Independent.queries{1} = AuditedIndependent.queries{2} ==>
    ={res,glob A,Independent.secrethistory} /\
    Independent.rawhistory{1} = PrefixAudit.history{2} /\
    Independent.queries{1} = AuditedIndependent.queries{2}].
proof.
  proc (={Independent.secrethistory} /\
    Independent.rawhistory{1} = PrefixAudit.history{2} /\
    Independent.queries{1} = AuditedIndependent.queries{2}) => //.
  + conseq audited_hash_observation; smt().
  by proc; inline Independent.derive; sp 0 1; wp; if; auto.
qed.

lemma audited_game_observation
  (A <: PrefixContext {-Independent,-AuditedIndependent,-PrefixAudit}) n q &m :
  Pr[IndependentGame(A).run() @ &m : res] =
  Pr[AuditedGame(A).run(n,q) @ &m : res].
proof.
  byequiv (_ : ={glob A} ==> ={res}) => //.
  proc; call (audited_context_observation A);
    inline Independent.init AuditedIndependent.init PrefixAudit.init; auto.
qed.

lemma audited_game_state
  (A <: PrefixContext {-Independent,-AuditedIndependent,-PrefixAudit}) :
  equiv[IndependentGame(A).run ~ AuditedGame(A).run : ={glob A} ==>
    ={res,glob A,Independent.secrethistory} /\
    Independent.rawhistory{1} = PrefixAudit.history{2} /\
    Independent.queries{1} = AuditedIndependent.queries{2}].
proof.
  proc; call (audited_context_observation A);
    inline Independent.init AuditedIndependent.init PrefixAudit.init; auto.
qed.

lemma audited_game_hoare
  (A <: PrefixContext {-Independent,-AuditedIndependent,-PrefixAudit})
  (pre : (glob A) -> bool) (post : raw_input list -> bool) :
  hoare[IndependentGame(A).run : pre (glob A) ==> post Independent.queries] =>
  hoare[AuditedGame(A).run : pre (glob A) ==> post AuditedIndependent.queries].
proof.
  move=> h.
  have he : equiv[AuditedGame(A).run ~ IndependentGame(A).run :
    ={glob A} ==> AuditedIndependent.queries{1} = Independent.queries{2}].
  + symmetry; conseq (audited_game_state A); auto.
  conseq he h.
  + by move=> &m hp; exists (glob A){m}.
  by auto.
qed.

lemma audited_hash_step n q k :
  hoare[AuditedIndependent.hash :
    audit_inv n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls PrefixAudit.tags /\
    PrefixAudit.calls = k ==>
    audit_inv n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls PrefixAudit.tags /\
    PrefixAudit.calls = (if k < q then k+1 else k)].
proof. by proc; call (audit_step n q k); auto. qed.

lemma audited_bad_step n q k : 0 <= n <= 256 =>
  phoare[AuditedIndependent.hash :
    audit_inv n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls PrefixAudit.tags /\
    PrefixAudit.calls = k /\ k < q /\ !PrefixAudit.bad ==> PrefixAudit.bad] <=
    ((max 0 k)%r * (1%r/2%r)^n).
proof. move=> hn; proc; call (audit_bad_step n q k hn); auto. qed.

lemma audited_prefix_collision
  (A <: PrefixContext {-Independent,-AuditedIndependent,-PrefixAudit}) n q &m :
  0 <= n <= 256 => 0 <= q =>
  Pr[AuditedGame(A).run(n,q) @ &m : PrefixAudit.bad] <=
    (q*(q-1))%r / 2%r * (1%r/2%r)^n.
proof.
  move=> hn hq; rewrite -(audit_sum_closed n q hq).
  fel 1 PrefixAudit.calls (fun i => i%r * (1%r/2%r)^n) q PrefixAudit.bad
    [PrefixAudit.hash : (PrefixAudit.calls < q)]
    (audit_inv n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls PrefixAudit.tags) => //.
  + by rewrite /audit_inv; smt().
  + by inline AuditedIndependent.init PrefixAudit.init; auto; rewrite /audit_inv; smt().
  + exists* PrefixAudit.calls; elim* => k;
    conseq (audit_bad_step n q k hn); smt().
  + move=> c; conseq (audit_step n q c); smt().
  move=> b c; proc; rcondf 2;
    first by auto; rewrite /audit_inv; smt().
  sp 1; if; auto.
qed.
