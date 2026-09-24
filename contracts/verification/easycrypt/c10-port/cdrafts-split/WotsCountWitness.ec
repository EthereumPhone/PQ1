(* An accepted count retains both its exact input and the actual WOTS root. *)
require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawWots.
require import RawCountRecorded WotsReferenceRoot.

lemma count_retains_wots_witness seed0 layer0 tree0 kp0 message0 root0 :
  hoare [RawWots(PreparationView(Independent)).count :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 ==>
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 /\
    (res<>None => 0 <= (oget res).`1 < signing_budget /\ count_accepts (oget res).`2 /\
      Independent.rawhistory.[wots_count_input seed0 layer0 tree0 kp0 message0 (oget res).`1]
        = Some (oget res).`2)].
proof.
  conseq (raw_count_recorded seed0 layer0 tree0 kp0 message0)
    (count_keeps_wots_root seed0 layer0 tree0 kp0 root0); smt().
qed.
