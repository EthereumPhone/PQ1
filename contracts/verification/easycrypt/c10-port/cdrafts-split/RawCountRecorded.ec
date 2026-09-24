(* A successful bounded WOTS search returns its actual accepted table entry. *)
require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind MonotoneHistory.

op wots_count_input seed layer tree kp message counter =
  seed ++ address layer tree 0 kp 0 0 0 ++ pad message ++ be 32 counter.

lemma hash_records_input x0 :
  hoare [Independent.hash : x=x0 ==> Independent.rawhistory.[x0]=Some res].
proof. proc; sp 1; if; auto; smt(get_set_sameE domE). qed.

lemma raw_count_recorded seed0 layer0 tree0 kp0 message0 :
  hoare [RawWots(PreparationView(Independent)).count :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 ==>
    res<>None => 0 <= (oget res).`1 < signing_budget /\ count_accepts (oget res).`2 /\
    Independent.rawhistory.[wots_count_input seed0 layer0 tree0 kp0 message0 (oget res).`1]
      = Some (oget res).`2].
proof.
  proc; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    0<=i<=signing_budget /\ (result<>None =>
      0 <= (oget result).`1 < signing_budget /\ count_accepts (oget result).`2 /\
      Independent.rawhistory.[wots_count_input seed0 layer0 tree0 kp0 message0 (oget result).`1]
        = Some (oget result).`2)).
  + exists* i; elim* => i0; wp.
    call (hash_records_input (wots_count_input seed0 layer0 tree0 kp0 message0 i0)).
    auto; rewrite /wots_count_input; smt().
  auto; smt().
qed.

lemma raw_count_extends s0 h0 :
  hoare [RawWots(PreparationView(Independent)).count :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; while (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + wp; call (independent_hash_extends s0 h0); auto.
  auto.
qed.
