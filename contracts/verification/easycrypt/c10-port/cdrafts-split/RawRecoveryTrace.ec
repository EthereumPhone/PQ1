(* Every actual WOTS recovery records its counter and, on acceptance, all suffixes. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import RawCountRecorded WotsRecoveryTrace RecoveryTraceOracle.

op wots_recovery_trace h seed layer tree kp message sigma count result =
  exists d, h.[wots_count_input seed layer tree kp message count]=Some d /\
    if count_accepts d then
      recovery_prefix h seed layer tree kp d sigma 43 /\
      exists leaf, h.[recovery_leaf_input h seed layer tree kp d sigma]=Some leaf /\ result=node leaf
    else result=nseq 16 0.

lemma raw_recovery_recorded seed0 layer0 tree0 kp0 message0 sigma0 count0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sigma=sigma0 /\ count=count0 ==>
    wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 kp0 message0 sigma0 count0 res].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ sigma=sigma0 /\
    Independent.rawhistory.[wots_count_input seed0 layer0 tree0 kp0 message0 count0]=Some d).
  + call (hash_records_input (wots_count_input seed0 layer0 tree0 kp0 message0 count0)).
    auto; rewrite /wots_count_input; smt().
  exists* d; elim* => d0; sp 1; if; last by auto; rewrite /wots_recovery_trace; smt().
  seq 3 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ sigma=sigma0 /\ d=d0 /\ count_accepts d0 /\
    Independent.rawhistory.[wots_count_input seed0 layer0 tree0 kp0 message0 count0]=Some d0 /\
    recovery_prefix Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 43 /\
    elements=recovery_elements Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 43).
  + while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ sigma=sigma0 /\ d=d0 /\ count_accepts d0 /\ 0<=i<=43 /\
      Independent.rawhistory.[wots_count_input seed0 layer0 tree0 kp0 message0 count0]=Some d0 /\
      recovery_prefix Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 i /\
      elements=recovery_elements Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 i).
    - exists* i,elements; elim* => i0 values; wp.
      call (chain_records_recovery seed0 layer0 tree0 kp0 d0 sigma0 i0 values
        (wots_count_input seed0 layer0 tree0 kp0 message0 count0) d0).
      auto; smt(recovery_prefix_add recovery_elements_step).
    auto; rewrite /recovery_prefix /recovery_elements; smt(range_geq).
  exists* elements; elim* => values; wp.
  call (hash_records_recovery seed0 layer0 tree0 kp0 d0 sigma0 43 values
    (wots_count_input seed0 layer0 tree0 kp0 message0 count0) d0
    (seed0 ++ address layer0 tree0 1 kp0 0 0 0 ++ flatten values)).
  auto; rewrite /wots_recovery_trace /recovery_leaf_input; smt().
qed.
