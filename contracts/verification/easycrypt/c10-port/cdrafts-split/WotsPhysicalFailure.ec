(* Actual count exhaustion leaves a persistent rejected schedule in Shared.
   This is a physical-cache statement, not a prefix-game event transfer. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawWots RawCountRecorded PersistentGrind ByteSession.
require import MemoRejectCompletion WotsRejectDomain.

lemma memo_complete_rejection_extends accept h h' xs :
  extends h h' => memo_complete_rejection accept h xs => memo_complete_rejection accept h' xs.
proof.
  rewrite /extends /memo_complete_rejection; move=> he /allP ha.
  apply/allP => x hx; have hh := ha x hx; smt(domE).
qed.

lemma wots_domain_exhausted_extends seed n h h' :
  extends h h' => wots_domain_exhausted seed n h => wots_domain_exhausted seed n h'.
proof.
  move=> he; rewrite /wots_domain_exhausted => -[c [hc hr]].
  exists c; split; first exact hc.
  exact (memo_complete_rejection_extends count_accepts h h' _ he hr).
qed.

lemma physical_hash_history h0 x0 :
  hoare[PreparationView(Physical).hash : Shared.history=h0 /\ x=x0 ==>
    extends h0 Shared.history /\ Shared.history.[x0]=Some res].
proof.
  proc; call (hash_history h0 x0); auto; rewrite /extends; smt(get_setE domE).
qed.

lemma physical_count_rejected seed0 layer0 tree0 kp0 message0 :
  hoare[RawWots(PreparationView(Physical)).count :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 ==>
    res=None => forall j, 0<=j<signing_budget => exists d,
      Shared.history.[wots_count_input seed0 layer0 tree0 kp0 message0 j]=Some d /\ !count_accepts d].
proof.
  proc; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    0<=i<=signing_budget /\ (result=None => forall j, 0<=j<i => exists d,
      Shared.history.[wots_count_input seed0 layer0 tree0 kp0 message0 j]=Some d /\ !count_accepts d)).
  + exists* i, Shared.history; elim* => i0 h0; wp.
    call (physical_hash_history h0 (wots_count_input seed0 layer0 tree0 kp0 message0 i0)).
    auto; rewrite /wots_count_input /extends; smt().
  auto; smt().
qed.

lemma physical_count_complete seed0 layer0 tree0 kp0 message0 :
  hoare[RawWots(PreparationView(Physical)).count :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 ==>
    res=None => memo_complete_rejection count_accepts Shared.history
      (wots_count_schedule (wots_context_stem seed0 (wots_context_bytes layer0 tree0 kp0 message0)) signing_budget)].
proof.
  conseq (physical_count_rejected seed0 layer0 tree0 kp0 message0) => //.
  move=> &hr _ result history hp hn; rewrite wots_count_schedule_actual /memo_complete_rejection all_map.
  apply/allP => j; rewrite mem_range => hj; have [d [hd ha]] := hp hn j hj.
  by rewrite /preim hd /=; smt(domE).
qed.

lemma physical_count_exhaustion seed0 layer0 tree0 kp0 message0 :
  size message0=16 => byte_values message0 =>
  hoare[RawWots(PreparationView(Physical)).count :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 ==>
    res=None => wots_domain_exhausted seed0 signing_budget Shared.history].
proof.
  move=> hw hb; have [c [hc hs]] := wots_context_covered seed0 layer0 tree0 kp0 message0 hw hb.
  conseq (physical_count_complete seed0 layer0 tree0 kp0 message0) => //.
  move=> &hr _ result history hp hn; rewrite /wots_domain_exhausted; exists c; split; first exact hc.
  rewrite hs -wots_context_stem_actual; exact (hp hn).
qed.
