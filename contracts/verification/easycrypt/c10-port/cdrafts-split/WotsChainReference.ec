(* The actual chain completes one retained key-generation reference. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import LinearChain RawChainTrace WotsReference WotsReferenceStep WotsReferenceOracle.

lemma chain_keeps_wots_reference seed0 layer0 tree0 kp0 n values key sd :
  hoare [RawWots(PreparationView(Independent)).chain :
    0 <= n /\ wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n = values /\
    Independent.secrethistory.[key] = Some sd ==>
    0 <= n /\ wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n = values /\
    Independent.secrethistory.[key] = Some sd].
proof.
  proc; while (0 <= n /\ wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n = values /\
    Independent.secrethistory.[key] = Some sd).
  + wp; call (hash_keeps_wots_reference seed0 layer0 tree0 kp0 n values key sd); auto.
  auto.
qed.

lemma chain_completes_wots_reference seed0 layer0 tree0 kp0 n values sd :
  hoare [RawWots(PreparationView(Independent)).chain :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=n /\
    current=node sd /\ start=0 /\ stop=7 /\ 0<=n /\
    0 <= n /\ wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n = values /\
    Independent.secrethistory.[wots_key layer0 tree0 kp0 n] = Some sd ==>
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 (n+1) /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 (n+1)
      = rcons values (pad res)].
proof.
  conseq (raw_chain_recorded seed0 layer0 tree0 kp0 n (node sd) 0 7)
    (chain_keeps_wots_reference seed0 layer0 tree0 kp0 n values (wots_key layer0 tree0 kp0 n) sd).
  + smt().
  smt(wots_reference_finish).
qed.
