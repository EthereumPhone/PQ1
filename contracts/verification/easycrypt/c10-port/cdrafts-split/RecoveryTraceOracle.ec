(* Memoized hash and chain calls preserve the completed recovery suffixes. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind AcceptedContexts MonotoneHistory RawChainTrace RawCountRecorded.
require import WotsRecoveryTrace LinearChain.

lemma hash_keeps_recovery seed0 layer0 tree0 kp0 d0 sigma0 n values key value :
  hoare [Independent.hash :
    recovery_prefix Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n /\
    recovery_elements Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n=values /\
    Independent.rawhistory.[key]=Some value ==>
    recovery_prefix Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n /\
    recovery_elements Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n=values /\
    Independent.rawhistory.[key]=Some value].
proof.
  proc; sp 1; if; auto; smt(recovery_prefix_extends extends_insert get_setE domE).
qed.

lemma hash_records_recovery seed0 layer0 tree0 kp0 d0 sigma0 n values key value input0 :
  hoare [Independent.hash :
    recovery_prefix Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n /\
    recovery_elements Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n=values /\
    Independent.rawhistory.[key]=Some value /\ x=input0 ==>
    recovery_prefix Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n /\
    recovery_elements Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n=values /\
    Independent.rawhistory.[key]=Some value /\ Independent.rawhistory.[input0]=Some res].
proof.
  conseq (hash_keeps_recovery seed0 layer0 tree0 kp0 d0 sigma0 n values key value)
    (hash_records_input input0); smt().
qed.

lemma chain_keeps_recovery seed0 layer0 tree0 kp0 d0 sigma0 n values key value :
  hoare [RawWots(PreparationView(Independent)).chain :
    recovery_prefix Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n /\
    recovery_elements Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n=values /\
    Independent.rawhistory.[key]=Some value ==>
    recovery_prefix Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n /\
    recovery_elements Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n=values /\
    Independent.rawhistory.[key]=Some value].
proof.
  proc; while (recovery_prefix Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n /\
    recovery_elements Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n=values /\
    Independent.rawhistory.[key]=Some value).
  + wp; call (hash_keeps_recovery seed0 layer0 tree0 kp0 d0 sigma0 n values key value); auto.
  auto.
qed.

lemma chain_records_recovery seed0 layer0 tree0 kp0 d0 sigma0 n values key value :
  hoare [RawWots(PreparationView(Independent)).chain :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=n /\
    current=nth (nseq 16 0) sigma0 n /\ start=digit 3 d0 n /\ stop=7 /\
    recovery_prefix Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n /\
    recovery_elements Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n=values /\
    Independent.rawhistory.[key]=Some value ==>
    recovery_prefix Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n /\
    recovery_elements Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n=values /\
    Independent.rawhistory.[key]=Some value /\
    linear_recorded Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 n)
      (nth (nseq 16 0) sigma0 n) (range (digit 3 d0 n) 7) /\
    res=recovery_endpoint Independent.rawhistory seed0 layer0 tree0 kp0 d0 sigma0 n].
proof.
  conseq (raw_chain_recorded seed0 layer0 tree0 kp0 n (nth (nseq 16 0) sigma0 n) (digit 3 d0 n) 7)
    (chain_keeps_recovery seed0 layer0 tree0 kp0 d0 sigma0 n values key value);
    rewrite /recovery_endpoint; smt(raw_digit_bounds).
qed.
