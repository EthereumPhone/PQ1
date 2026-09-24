(* A rejected WOTS count cannot match a retained leaf without a zero-node event. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind AcceptedContexts WotsReference WotsLeafReference WotsReferenceRoot.
require import RawCountRecorded RawWotsRecovery PublicNodeZero.

lemma wots_zero_is_public h s seed layer tree kp root :
  wots_root h s seed layer tree kp root => root=nseq 16 0 => public_node_zero h.
proof.
  rewrite /wots_root /public_node_zero.
  move=> [hp [d [hd he]]] hz.
  exists (wots_leaf_input h s seed layer tree kp) d; smt().
qed.

lemma public_zero_extends h h' : extends h h' => public_node_zero h => public_node_zero h'.
proof. rewrite /extends /public_node_zero; smt(). qed.

lemma invalid_sum_matches_only_zero seed0 layer0 tree0 kp0 message0 count0 d0 h0 s0 root0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ count=count0 /\
    !count_accepts d0 /\ h0.[wots_count_input seed0 layer0 tree0 kp0 message0 count0]=Some d0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    wots_root h0 s0 seed0 layer0 tree0 kp0 root0 ==>
    res=root0 => public_node_zero h0].
proof.
  conseq (raw_wots_invalid_sum_sentinel seed0 layer0 tree0 kp0 message0 count0 d0 h0 s0);
    smt(wots_zero_is_public).
qed.
