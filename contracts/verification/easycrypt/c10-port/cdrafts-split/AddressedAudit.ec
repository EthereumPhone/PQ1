(* Private collision observer over the unchanged independent memo oracle.
   The cap only gates its private flag/counter; every fresh call samples the
   original full_digest and every caller receives the original memo result. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer RawKeygen PrefixGuess PrefixIdeal.
require import AddressedBuckets AddressedBucketHistory.

module AddressedAudit = {
  var rawhistory, secrethistory : (raw_input,digest) fmap
  var queries : raw_input list
  var bad : bool
  var calls, cap : int
  proc init(k : int) : unit = {
    rawhistory <- empty; secrethistory <- empty; queries <- [];
    bad <- false; calls <- 0; cap <- k;
  }
  proc hash(x : raw_input) : digest = {
    var hits, d;
    queries <- rcons queries x;
    if (x \notin rawhistory) {
      hits <- addressed_hits rawhistory (addressed_label x);
      d <$ full_digest;
      if (0<size hits /\ size hits<=cap) {
        bad <- bad \/ node d \in hits;
        calls <- calls+1;
      }
      rawhistory.[x] <- d;
    }
    return oget rawhistory.[x];
  }
  proc derive(tail : raw_input) : digest = {
    var d;
    if (tail \notin secrethistory) { d <$ full_digest; secrethistory.[tail] <- d; }
    return oget secrethistory.[tail];
  }
}.

module AddressedAuditGame (A : PrefixContext) = {
  proc run(k : int) : bool = {
    var result;
    AddressedAudit.init(k); result <@ A(AddressedAudit).run();
    return result;
  }
}.

op addressed_audit_invariant h calls cap bad =
  calls<=addressed_excess h /\ (label_collision h => bad \/ oversized_bucket h cap).

lemma addressed_audit_hash_invariant :
  hoare [AddressedAudit.hash :
    addressed_audit_invariant AddressedAudit.rawhistory AddressedAudit.calls AddressedAudit.cap AddressedAudit.bad ==>
    addressed_audit_invariant AddressedAudit.rawhistory AddressedAudit.calls AddressedAudit.cap AddressedAudit.bad].
proof.
  proc; sp 1; if; last by auto.
  auto; rewrite /addressed_audit_invariant;
    smt(addressed_excess_insert addressed_hits_positive addressed_insert_coverage b2i_ge0).
qed.

lemma addressed_audit_derive_invariant :
  hoare [AddressedAudit.derive :
    addressed_audit_invariant AddressedAudit.rawhistory AddressedAudit.calls AddressedAudit.cap AddressedAudit.bad ==>
    addressed_audit_invariant AddressedAudit.rawhistory AddressedAudit.calls AddressedAudit.cap AddressedAudit.bad].
proof. proc; if; auto. qed.

lemma addressed_audit_context_invariant (A <: PrefixContext {-AddressedAudit}) :
  hoare [A(AddressedAudit).run :
    addressed_audit_invariant AddressedAudit.rawhistory AddressedAudit.calls AddressedAudit.cap AddressedAudit.bad ==>
    addressed_audit_invariant AddressedAudit.rawhistory AddressedAudit.calls AddressedAudit.cap AddressedAudit.bad].
proof.
  proc (addressed_audit_invariant AddressedAudit.rawhistory AddressedAudit.calls AddressedAudit.cap AddressedAudit.bad) => //.
  + exact addressed_audit_hash_invariant.
  exact addressed_audit_derive_invariant.
qed.

lemma addressed_audit_game_invariant (A <: PrefixContext {-AddressedAudit}) k0 :
  hoare [AddressedAuditGame(A).run : k=k0 ==>
    AddressedAudit.cap=k0 /\
    addressed_audit_invariant AddressedAudit.rawhistory AddressedAudit.calls AddressedAudit.cap AddressedAudit.bad].
proof.
  proc; call (addressed_audit_context_invariant A).
  inline AddressedAudit.init; auto; rewrite /addressed_audit_invariant;
    smt(addressed_excess_empty label_collision_empty).
qed.

lemma addressed_audit_hash_projection :
  equiv [Independent.hash ~ AddressedAudit.hash :
    ={x} /\ Independent.rawhistory{1}=AddressedAudit.rawhistory{2} /\
    Independent.secrethistory{1}=AddressedAudit.secrethistory{2} /\
    Independent.queries{1}=AddressedAudit.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=AddressedAudit.rawhistory{2} /\
    Independent.secrethistory{1}=AddressedAudit.secrethistory{2} /\
    Independent.queries{1}=AddressedAudit.queries{2}].
proof.
  proc; sp 1 1; if.
  + auto.
  + sp 0 1; wp; rnd; auto.
  auto.
qed.

lemma addressed_audit_context_projection (A <: PrefixContext {-Independent,-AddressedAudit}) :
  equiv [A(Independent).run ~ A(AddressedAudit).run :
    ={glob A} /\ Independent.rawhistory{1}=AddressedAudit.rawhistory{2} /\
    Independent.secrethistory{1}=AddressedAudit.secrethistory{2} /\
    Independent.queries{1}=AddressedAudit.queries{2} ==>
    ={res,glob A} /\ Independent.rawhistory{1}=AddressedAudit.rawhistory{2} /\
    Independent.secrethistory{1}=AddressedAudit.secrethistory{2} /\
    Independent.queries{1}=AddressedAudit.queries{2}].
proof.
  proc (Independent.rawhistory{1}=AddressedAudit.rawhistory{2} /\
    Independent.secrethistory{1}=AddressedAudit.secrethistory{2} /\
    Independent.queries{1}=AddressedAudit.queries{2}) => //.
  + exact addressed_audit_hash_projection.
  by sim.
qed.

lemma addressed_audit_game_projection (A <: PrefixContext {-Independent,-AddressedAudit}) k0 :
  equiv [IndependentGame(A).run ~ AddressedAuditGame(A).run : ={glob A} /\ k{2}=k0 ==>
    ={res,glob A} /\ Independent.rawhistory{1}=AddressedAudit.rawhistory{2} /\
    Independent.secrethistory{1}=AddressedAudit.secrethistory{2} /\
    Independent.queries{1}=AddressedAudit.queries{2}].
proof.
  proc; call (addressed_audit_context_projection A); inline Independent.init AddressedAudit.init; auto.
qed.
