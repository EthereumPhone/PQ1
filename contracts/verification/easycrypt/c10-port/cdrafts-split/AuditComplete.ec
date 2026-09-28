(* External Q research: when the transcript fits the monitor budget, the
   monitor covers every distinct public raw input in the final oracle table. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixAudit AuditPrefix.

op prefixes_recorded (n : int) (h : (raw_input,digest) fmap) (tags : bool list list) =
  forall x d, h.[x] = Some d => take n d \in tags.
op prefixes_unique n (h : (raw_input,digest) fmap) =
  forall x y u v, h.[x] = Some u => h.[y] = Some v =>
    take n u = take n v => x = y.

lemma recorded_update n h tags x d : prefixes_recorded n h tags =>
  prefixes_recorded n h.[x <- d] (rcons tags (take n d)).
proof.
  rewrite /prefixes_recorded => hr y u hu.
  rewrite get_setE in hu; smt(mem_rcons).
qed.
lemma unique_update n h tags x d :
  prefixes_recorded n h tags => prefixes_unique n h =>
  !(take n d \in tags) => prefixes_unique n h.[x <- d].
proof.
  rewrite /prefixes_recorded /prefixes_unique => hr hu hn y z u v hy hz he.
  rewrite get_setE in hy; rewrite get_setE in hz; smt().
qed.

op audit_complete (n q width limit calls : int) (tags : bool list list)
  (history : (raw_input,digest) fmap) (queries : raw_input list) (bad : bool) =
  width = n /\ limit = q /\ 0 <= q /\ calls = min q (size queries) /\
  (size queries <= q => prefixes_recorded n history tags /\
    (!bad => prefixes_unique n history)).

lemma audited_hash_complete n q :
  hoare[AuditedIndependent.hash :
    audit_complete n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls
      PrefixAudit.tags PrefixAudit.history AuditedIndependent.queries PrefixAudit.bad ==>
    audit_complete n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls
      PrefixAudit.tags PrefixAudit.history AuditedIndependent.queries PrefixAudit.bad].
proof.
  proc; inline PrefixAudit.hash; sp 3; if; wp; if; auto;
    rewrite /audit_complete; smt(size_rcons recorded_update unique_update).
qed.

lemma audited_derive_complete n q :
  hoare[AuditedIndependent.derive :
    audit_complete n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls
      PrefixAudit.tags PrefixAudit.history AuditedIndependent.queries PrefixAudit.bad ==>
    audit_complete n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls
      PrefixAudit.tags PrefixAudit.history AuditedIndependent.queries PrefixAudit.bad].
proof. by proc; inline Independent.derive; sp 1; if; auto. qed.

lemma audited_context_complete
  (A <: PrefixContext {-Independent,-AuditedIndependent,-PrefixAudit}) n q :
  hoare[A(AuditedIndependent).run :
    audit_complete n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls
      PrefixAudit.tags PrefixAudit.history AuditedIndependent.queries PrefixAudit.bad ==>
    audit_complete n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls
      PrefixAudit.tags PrefixAudit.history AuditedIndependent.queries PrefixAudit.bad].
proof.
  proc (audit_complete n q PrefixAudit.width PrefixAudit.limit PrefixAudit.calls
      PrefixAudit.tags PrefixAudit.history AuditedIndependent.queries PrefixAudit.bad) => //.
  + conseq (audited_hash_complete n q); auto.
  conseq (audited_derive_complete n q); auto.
qed.

lemma audited_game_complete
  (A <: PrefixContext {-Independent,-AuditedIndependent,-PrefixAudit}) n0 q0 :
  0 <= q0 => hoare[AuditedGame(A).run : n = n0 /\ q = q0 ==>
    size AuditedIndependent.queries <= q0 =>
    !PrefixAudit.bad => prefixes_unique n0 PrefixAudit.history].
proof.
  move=> hq; proc; call (audited_context_complete A n0 q0).
  inline AuditedIndependent.init PrefixAudit.init; auto;
    rewrite /audit_complete /prefixes_recorded /prefixes_unique; smt(emptyE size_ge0).
qed.
