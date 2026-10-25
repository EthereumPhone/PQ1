(* The actual ordinary FORS call has a public root/path projection. Its
   selected secret is exactly the memoized private entry, even when earlier
   trusted replay caused the two passive query logs to differ. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest.
require import ForsPrivateLeaves ForsLeafView WrapperForsPlan WrapperMemoProjection.

lemma wrapper_fors_one_public_plan_full seed_ref ht_ref tree_ref target_ref :
  0<=target_ref<2048 =>
  equiv [RawForest(PreparationView(Independent)).one ~
    WrapperForsPublicPlan(ConcreteForsLeaf(PreparationView(Independent))).one :
    arg{1}=(seed_ref,ht_ref,tree_ref,target_ref) /\ ={arg,glob Independent} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    res{1}.`2=res{2}.`2 /\ res{1}.`3=res{2}.`1 /\
    fors_private_key ht_ref tree_ref target_ref \in Independent.secrethistory{1} /\
    res{1}.`1=node (oget Independent.secrethistory{1}.[fors_private_key ht_ref tree_ref target_ref])].
proof.
  move=> ht.
  transitivity WrapperForsOneViews.recover
    (={arg,glob Independent} ==> ={res,glob Independent})
    (arg{1}=(seed_ref,ht_ref,tree_ref,target_ref) /\ ={arg,glob Independent} ==>
      ={Independent.rawhistory,Independent.secrethistory} /\
      res{1}.`2=res{2}.`2 /\ res{1}.`3=res{2}.`1 /\
      fors_private_key ht_ref tree_ref target_ref \in Independent.secrethistory{1} /\
      res{1}.`1=node (oget Independent.secrethistory{1}.[fors_private_key ht_ref tree_ref target_ref])) => //.
  + smt().
  + exact wrapper_fors_one_observed.
  transitivity WrapperForsOneViews.direct
    (arg{1}=(seed_ref,ht_ref,tree_ref,target_ref) /\ ={arg,glob Independent} ==>
      ={res,Independent.rawhistory,Independent.secrethistory})
    (arg{1}=(seed_ref,ht_ref,tree_ref,target_ref) /\ ={arg,glob Independent} ==>
      ={Independent.rawhistory,Independent.secrethistory} /\
      res{1}.`2=res{2}.`2 /\ res{1}.`3=res{2}.`1 /\
      fors_private_key ht_ref tree_ref target_ref \in Independent.secrethistory{1} /\
      res{1}.`1=node (oget Independent.secrethistory{1}.[fors_private_key ht_ref tree_ref target_ref])) => //.
  + smt().
  + exact (wrapper_fors_recovery_eliminated seed_ref ht_ref tree_ref target_ref ht).
  transitivity WrapperForsOneViews.late
    (={arg,glob Independent} ==> ={res,glob Independent})
    (arg{1}=(seed_ref,ht_ref,tree_ref,target_ref) /\ ={arg,glob Independent} ==>
      ={Independent.rawhistory,Independent.secrethistory} /\
      res{1}.`2=res{2}.`2 /\ res{1}.`3=res{2}.`1 /\
      fors_private_key ht_ref tree_ref target_ref \in Independent.secrethistory{1} /\
      res{1}.`1=node (oget Independent.secrethistory{1}.[fors_private_key ht_ref tree_ref target_ref])) => //.
  + smt().
  + exact wrapper_fors_one_delayed.
  exact (wrapper_fors_delayed_public_plan seed_ref ht_ref tree_ref target_ref ht).
qed.

lemma wrapper_fors_one_public_plan seed_ref ht_ref tree_ref target_ref :
  0<=target_ref<2048 =>
  equiv [RawForest(PreparationView(Independent)).one ~
    WrapperForsPublicPlan(ConcreteForsLeaf(PreparationView(Independent))).one :
    arg{1}=(seed_ref,ht_ref,tree_ref,target_ref) /\
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    res{1}.`2=res{2}.`2 /\ res{1}.`3=res{2}.`1 /\
    fors_private_key ht_ref tree_ref target_ref \in Independent.secrethistory{1} /\
    res{1}.`1=node (oget Independent.secrethistory{1}.[fors_private_key ht_ref tree_ref target_ref])].
proof.
  move=> ht.
  transitivity RawForest(PreparationView(Independent)).one
    (={arg,Independent.rawhistory,Independent.secrethistory} ==>
      ={res,Independent.rawhistory,Independent.secrethistory})
    (arg{1}=(seed_ref,ht_ref,tree_ref,target_ref) /\ ={arg,glob Independent} ==>
      ={Independent.rawhistory,Independent.secrethistory} /\
      res{1}.`2=res{2}.`2 /\ res{1}.`3=res{2}.`1 /\
      fors_private_key ht_ref tree_ref target_ref \in Independent.secrethistory{1} /\
      res{1}.`1=node (oget Independent.secrethistory{1}.[fors_private_key ht_ref tree_ref target_ref])) => //.
  + smt().
  + exact (wrapper_fors_one_table_projection WrapperOriginalForsOne).
  exact (wrapper_fors_one_public_plan_full seed_ref ht_ref tree_ref target_ref ht).
qed.
