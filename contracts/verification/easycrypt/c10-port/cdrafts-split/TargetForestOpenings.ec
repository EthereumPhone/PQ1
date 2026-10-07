(* Ordinary FORS secrets are opened only for the digest coordinates being signed. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest.
require import RawShuffle RawShufflePermutation ForsPrivateLeaves ForsLeafView LeafForestView.
require import TargetOracleSplit TargetByteView TargetTableProjection.

op forest_opens_input input ht digest =
  exists tree, 0<=tree<12 /\ input=fors_private_key ht tree (forest_index digest tree).

lemma internal_tree_preserves_opening flag :
  hoare [LeafFors(TargetLeaf(ObservedTarget(Independent))).tree :
    OriginalTargetState.revealed=flag ==> OriginalTargetState.revealed=flag].
proof. proc*; call (_ : true ==> true); first by trivial. auto. qed.

lemma ordinary_secret_opening flag input ht0 tree0 index0 :
  hoare [LeafFors(TargetLeaf(ObservedTarget(Independent))).sign :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=input /\
    ht=ht0 /\ tree=tree0 /\ target=index0 ==>
    OriginalTargetState.revealed=(flag \/ input=fors_private_key ht0 tree0 index0)].
proof.
  proc; wp; call (_ : true ==> true); first by trivial.
  inline ObservedTarget(Independent).secret ObservedTarget(Independent).derive.
  wp; call (_ : true ==> true); first by trivial.
  auto; smt().
qed.

lemma forest_one_opening flag input ht0 tree0 index0 :
  hoare [LeafForest(PreparationView(TargetPrefix(ObservedTarget(Independent))),
      TargetLeaf(ObservedTarget(Independent))).one :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=input /\
    ht=ht0 /\ tree=tree0 /\ leaf=index0 ==>
    OriginalTargetState.revealed=(flag \/ input=fors_private_key ht0 tree0 index0)].
proof.
  proc; call (_ : true ==> true); first by trivial.
  call (ordinary_secret_opening flag input ht0 tree0 index0); auto.
qed.

lemma forest_sign_opening flag input ht0 digest0 :
  hoare [LeafForest(PreparationView(TargetPrefix(ObservedTarget(Independent))),
      TargetLeaf(ObservedTarget(Independent))).sign :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=input /\ ht=ht0 /\ digest=digest0 ==>
    OriginalTargetState.revealed => flag \/ forest_opens_input input ht0 digest0].
proof.
  proc; call (_ : true ==> true); first by trivial.
  wp; call (_ : true ==> true); first by trivial.
  wp; call (_ : true ==> true); first by trivial.
  while (TargetConfig.input=input /\ ht=ht0 /\ digest=digest0 /\
    0<=step<=12 /\ perm_eq order (range 0 12) /\
    (OriginalTargetState.revealed => flag \/ forest_opens_input input ht0 digest0)).
  + wp; exists* OriginalTargetState.revealed, order, step; elim* => b order0 step0.
    call (forest_one_opening b input ht0 (nth 0 order0 step0) (forest_index digest0 (nth 0 order0 step0))).
    auto; rewrite /forest_opens_input; smt(perm_eq_size perm_eq_mem mem_nth mem_range size_range).
  wp; call (raw_shuffle_permutation (PreparationView(TargetPrefix(ObservedTarget(Independent)))) 12 independent_hash_ll).
  call (_ : true ==> true); first by trivial.
  auto; smt().
qed.
