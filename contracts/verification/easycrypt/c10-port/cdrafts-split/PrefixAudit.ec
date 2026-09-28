(* External Q research: normal uncapped random-oracle observations with a
   private collision monitor covering only the first q physical hash calls.
   A separate reduction is still required for any full forgery conclusion. *)
require import AllCore List Distr FMap StdOrder StdBigop.
require import C10RawOracle C10Randomizer DigestPrefix.
require FelTactic.
import RField RealOrder Bigreal BRA.

module PrefixAudit = {
  var history : (raw_input,digest) fmap
  var tags : bool list list
  var calls, limit, width : int
  var bad : bool
  proc init(n q : int) : unit = {
    history <- empty; tags <- []; calls <- 0;
    limit <- q; width <- n; bad <- false;
  }
  proc hash(x : raw_input) : digest = {
    var y, result;
    result <- nseq 256 false;
    if (calls < limit) {
      if (x \notin history) {
        y <$ full_digest;
        bad <- bad \/ take width y \in tags;
        tags <- rcons tags (take width y);
        history.[x] <- y;
      }
      result <- oget history.[x]; calls <- calls+1;
    } else {
      if (x \notin history) { y <$ full_digest; history.[x] <- y; }
      result <- oget history.[x];
    }
    return result;
  }
}.

module type AuditClient (O : Hash) = {
  proc run() : unit { O.hash }
}.
module AuditGame (A : AuditClient) = {
  proc run(n q : int) : bool = {
    PrefixAudit.init(n,q);
    A(PrefixAudit).run();
    return PrefixAudit.bad;
  }
}.

op audit_inv (n q width limit calls : int) (tags : bool list list) =
  width = n /\ limit = q /\ 0 <= calls <= q /\ size tags <= calls.

lemma audit_step n q k :
  hoare[PrefixAudit.hash : audit_inv n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls PrefixAudit.tags /\ PrefixAudit.calls = k ==>
    audit_inv n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls PrefixAudit.tags /\ PrefixAudit.calls = (if k < q then k+1 else k)].
proof.
  proc; sp 1; if; last by if; auto; rewrite /audit_inv; smt().
  wp; if; auto; rewrite /audit_inv; smt(size_rcons).
qed.

lemma audit_bad_step n q k : 0 <= n <= 256 =>
  phoare[PrefixAudit.hash : audit_inv n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls PrefixAudit.tags /\ PrefixAudit.calls = k /\
    k < q /\ !PrefixAudit.bad ==> PrefixAudit.bad] <=
    ((max 0 k)%r * (1%r/2%r)^n).
proof.
  move=> hn.
  have hp : 0%r <= (1%r/2%r)^n by apply expr_ge0; smt().
  have hb : 0%r <= (max 0 k)%r * (1%r/2%r)^n by apply mulr_ge0; smt(le_fromint).
  proc; rcondt 2; first by auto; rewrite /audit_inv; smt().
  sp 1; wp; if.
  + wp; rnd; skip; rewrite /audit_inv => /> &m hk0 hkq hsize hk hbad hx.
    have hm := digest_prefix_list n PrefixAudit.tags{m} hn.
    smt(le_fromint).
  conseq (_ : _ ==> _ : =0%r) => //.
  by hoare; auto; smt().

qed.

lemma audit_collision_bound (A <: AuditClient {-PrefixAudit}) n q &m :
  0 <= n <= 256 => 0 <= q =>
  Pr[AuditGame(A).run(n,q) @ &m : PrefixAudit.bad] <=
    bigi predT (fun i => i%r * (1%r/2%r)^n) 0 q.
proof.
  move=> hn hq.
  fel 1 PrefixAudit.calls (fun i => i%r * (1%r/2%r)^n) q PrefixAudit.bad
    [PrefixAudit.hash : (PrefixAudit.calls < q)] (audit_inv n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls PrefixAudit.tags) => //.
  + by rewrite /audit_inv; smt().
  + by inline PrefixAudit.init; auto; rewrite /audit_inv; smt().
  + exists* PrefixAudit.calls; elim* => k;
    conseq (audit_bad_step n q k hn); smt().
  + move=> c; conseq (audit_step n q c); smt().
  move=> b c; proc; rcondf 2; first by auto; rewrite /audit_inv; smt().
  sp 1; if; auto.
qed.

lemma audit_sum_closed n q : 0 <= q =>
  bigi predT (fun i => i%r * (1%r/2%r)^n) 0 q =
    (q*(q-1))%r / 2%r * (1%r/2%r)^n.
proof.
  by move=> hq; rewrite -BRA.mulr_suml Bigreal.sumidE 1:hq /=.
qed.

lemma audit_collision_explicit (A <: AuditClient {-PrefixAudit}) n q &m :
  0 <= n <= 256 => 0 <= q =>
  Pr[AuditGame(A).run(n,q) @ &m : PrefixAudit.bad] <=
    (q*(q-1))%r / 2%r * (1%r/2%r)^n.
proof.
  move=> hn hq; have h := audit_collision_bound A n q &m hn hq.
  by rewrite (audit_sum_closed n q hq) in h.
qed.

lemma audit_hash_lossless : islossless PrefixAudit.hash.
proof. proc; sp 1; if; wp; if; auto; smt(full_digest_ll). qed.

lemma audit_query_observation :
  equiv[Reference.hash ~ PrefixAudit.hash :
    ={x} /\ Reference.history{1} = PrefixAudit.history{2} ==>
    ={res} /\ Reference.history{1} = PrefixAudit.history{2}].
proof. by proc; sp 0 1; if{2}; wp; if; auto. qed.

lemma audit_context_observation (A <: Context {-Reference,-PrefixAudit}) :
  equiv[A(Reference).run ~ A(PrefixAudit).run :
    ={glob A} /\ Reference.history{1} = PrefixAudit.history{2} ==>
    ={res,glob A} /\ Reference.history{1} = PrefixAudit.history{2}].
proof.
  proc (Reference.history{1} = PrefixAudit.history{2}) => //.
  exact audit_query_observation.
qed.
