(* The actual recovery procedure consumes the accepted signing witness. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind WotsReference WotsReferenceRoot WotsLeafReference WotsSignWitness.
require import WotsSignatureValue RawCountRecorded RawWotsRecovery.

lemma raw_wots_recovers_opening seed0 layer0 tree0 kp0 message0 (signature0 : raw_input list * int) root0 h0 s0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    sigma=signature0.`1 /\ count=signature0.`2 /\
    wots_opening h0 s0 seed0 layer0 tree0 kp0 message0 root0 signature0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=root0].
proof.
  conseq (_ : exists d leaf,
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    sigma=signature0.`1 /\ count=signature0.`2 /\
    wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\
    wots_signature h0 s0 seed0 layer0 tree0 kp0 d signature0.`1 /\ count_accepts d /\
    h0.[wots_count_input seed0 layer0 tree0 kp0 message0 signature0.`2]=Some d /\
    h0.[wots_leaf_input h0 s0 seed0 layer0 tree0 kp0]=Some leaf /\ root0=node leaf /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==> res=root0).
  + rewrite /wots_opening /wots_root; smt().
  elim* => d leaf.
  conseq (raw_wots_recovers_reference seed0 layer0 tree0 kp0 message0 signature0.`1 signature0.`2 d leaf h0 s0); smt().
qed.
