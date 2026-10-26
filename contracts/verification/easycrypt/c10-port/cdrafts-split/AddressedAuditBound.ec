(* Conditional fundamental-lemma charge for the private observer. The caller
   and all private/public fresh samples retain their original distributions. *)
require import AllCore List Distr FMap StdOrder StdBigop FelTactic.
require import C10RawOracle RawKeygen PrefixGuess NodeDistribution AddressedBuckets AddressedBucketHistory AddressedAudit.
import RField RealOrder.

lemma addressed_audit_collision_bound (A <: PrefixContext {-AddressedAudit}) q k &m :
  0<=q => 0<=k =>
  Pr[AddressedAuditGame(A).run(k) @ &m : AddressedAudit.bad /\ AddressedAudit.calls<=q]
    <=q%r*k%r*(1%r/2%r)^128.
proof.
  move=> hq hk.
  fel 1 AddressedAudit.calls (fun _ => k%r*(1%r/2%r)^128) q AddressedAudit.bad
    [AddressedAudit.hash : (x \notin AddressedAudit.rawhistory /\
      0<size (addressed_hits AddressedAudit.rawhistory (addressed_label x)) /\
      size (addressed_hits AddressedAudit.rawhistory (addressed_label x))<=AddressedAudit.cap)]
    (AddressedAudit.cap=k) => //.
  + rewrite Bigreal.sumri_const 1:hq; smt().
  + by inline*; auto.
  + proc; rcondt 2; first by auto; smt().
    rcondt 4; first by auto; smt().
    sp 2; wp; rnd (fun d => node d \in hits); skip => // /> &hr *.
    have hm := node_history_mass (addressed_hits AddressedAudit.rawhistory{hr} (addressed_label x{hr})).
    have hp : 0%r<=(1%r/2%r)^128 by smt(expr_ge0).
    apply (ler_trans _ _ _ hm).
    apply ler_wpmul2r; first exact hp.
    by rewrite le_fromint.
  + move=> c; proc; rcondt 2; first by auto; smt().
    rcondt 4; first by auto; smt().
    by auto; smt().
  + move=> b c; proc; sp 1; if; last by auto.
    auto; smt().
qed.
