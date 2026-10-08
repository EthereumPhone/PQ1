(* The bounded signer selects one stable first accepting counter per message. *)
require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawCountRecorded.
require import PersistentGrind MonotoneHistory AcceptedContexts.

op rejected_counts h seed layer tree kp message n =
  forall c, 0<=c<n => exists d,
    h.[wots_count_input seed layer tree kp message c]=Some d /\ !count_accepts d.
op first_wots_count h seed layer tree kp message c d =
  0<=c<signing_budget /\ rejected_counts h seed layer tree kp message c /\
  h.[wots_count_input seed layer tree kp message c]=Some d /\ count_accepts d.

lemma rejected_counts_empty h seed layer tree kp message :
  rejected_counts h seed layer tree kp message 0.
proof. rewrite /rejected_counts; smt(). qed.
lemma rejected_counts_extends h h' seed layer tree kp message n :
  extends h h' => rejected_counts h seed layer tree kp message n =>
  rejected_counts h' seed layer tree kp message n.
proof. rewrite /extends /rejected_counts; smt(). qed.
lemma rejected_counts_next h seed layer tree kp message n d :
  rejected_counts h seed layer tree kp message n =>
  h.[wots_count_input seed layer tree kp message n]=Some d => !count_accepts d =>
  rejected_counts h seed layer tree kp message (n+1).
proof. rewrite /rejected_counts; smt(). qed.
lemma first_wots_count_extends h h' seed layer tree kp message c d :
  extends h h' => first_wots_count h seed layer tree kp message c d =>
  first_wots_count h' seed layer tree kp message c d.
proof. rewrite /first_wots_count /extends /rejected_counts; smt(). qed.
lemma first_wots_count_unique h seed layer tree kp message c d c' d' :
  first_wots_count h seed layer tree kp message c d =>
  first_wots_count h seed layer tree kp message c' d' => c=c' /\ d=d'.
proof. rewrite /first_wots_count /rejected_counts; smt(). qed.

lemma hash_records_with_history x0 h0 :
  hoare [Independent.hash : x=x0 /\ extends h0 Independent.rawhistory ==>
    extends h0 Independent.rawhistory /\ Independent.rawhistory.[x0]=Some res].
proof.
  conseq (hash_records_input x0) (independent_hash_extends empty h0);
    rewrite /extends; smt(emptyE).
qed.

lemma raw_count_first seed0 layer0 tree0 kp0 message0 :
  hoare [RawWots(PreparationView(Independent)).count :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 ==>
    res<>None => first_wots_count Independent.rawhistory seed0 layer0 tree0 kp0 message0
      (oget res).`1 (oget res).`2].
proof.
  proc; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    0<=i<=signing_budget /\
    (result=None => rejected_counts Independent.rawhistory seed0 layer0 tree0 kp0 message0 i) /\
    (result<>None => first_wots_count Independent.rawhistory seed0 layer0 tree0 kp0 message0
      (oget result).`1 (oget result).`2)).
  + exists* i,Independent.rawhistory; elim* => i0 h0; wp.
    call (hash_records_with_history (wots_count_input seed0 layer0 tree0 kp0 message0 i0) h0).
    auto; rewrite /wots_count_input /first_wots_count;
      smt(extends_refl rejected_counts_extends rejected_counts_next).
  auto; smt(rejected_counts_empty).
qed.
