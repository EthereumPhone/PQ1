(* A derivation already returned to the signer names the tree's reference leaf. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawSignature.
require import PathReplay RawForsPathReplay ForsPrivateLeaves ForsBuilderPrivate ForsPrivateEntry.

lemma fors_tree_known_secret seed0 ht0 tree0 target0 sd0 :
  hoare [RawFors(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    0 <= target0 < 2048 /\
    Independent.secrethistory.[fors_private_key ht0 tree0 target0] = Some sd0 ==>
    rows_width 11 res.`2 /\ exists d,
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 (node sd0)] = Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2).`1 = res.`1].
proof.
  conseq (fors_tree_private_path seed0 ht0 tree0 target0)
    (fors_tree_keeps_private_entry (fors_private_key ht0 tree0 target0) sd0); smt().
qed.

lemma fors_records_private_entry tail0 :
  hoare [PreparationView(Independent).fors : tail = tail0 ==>
    Independent.secrethistory.[fors_tag ++ tail0] = Some res].
proof.
  proc; inline *; sp; if; auto; smt(get_set_sameE domE).
qed.
