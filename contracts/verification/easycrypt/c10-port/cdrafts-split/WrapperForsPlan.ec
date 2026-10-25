(* A public FORS construction plan retains the root and authentication path.
   Its later secret is the already memoized value at the same full address.
   The local projection omits only the passive public-query log; it preserves
   both oracle tables and every returned component. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest RawSignature.
require import ForsPrivateLeaves ForsSignWitness ForsBuilderPrivate ForsLeafView.
require import PathReplay RawForsPathReplay RawChainCached WrapperPrivateSchedule WrapperForsReplay.

lemma wrapper_private_entry_total s0 key0 sd0 :
  phoare [Independent.derive :
    Independent.secrethistory=s0 /\ tail=key0 /\ s0.[key0]=Some sd0 ==>
    Independent.secrethistory=s0 /\ res=sd0] = 1%r.
proof. conseq independent_derive_ll (derive_existing_entry s0 key0 sd0); smt(). qed.

module WrapperForsOneViews = {
  proc recover(seed : raw_input, ht tree target : int) : raw_input * raw_input list * raw_input = {
    var signed, root;
    signed <@ ForsSignWitness(PreparationView(Independent)).sign(seed,ht,tree,target);
    root <@ RawFors(PreparationView(Independent)).recover(seed,ht,tree,target,signed.`1,signed.`2);
    return (signed.`1,signed.`2,root);
  }
  proc direct(seed : raw_input, ht tree target : int) : raw_input * raw_input list * raw_input = {
    var signed; signed <@ ForsSignWitness(PreparationView(Independent)).sign(seed,ht,tree,target);
    return signed;
  }
  proc late(seed : raw_input, ht tree target : int) : raw_input * raw_input list * raw_input = {
    var signed; signed <@ WrapperDeferredFors.sign(seed,ht,tree,target); return signed;
  }
}.
module WrapperForsPublicPlan (F : ForsLeafOracle) = {
  proc one(seed : raw_input, ht tree target : int) : raw_input * raw_input list = {
    var built; built <@ LeafFors(F).tree(seed,ht,tree,target); return built;
  }
}.

lemma wrapper_fors_one_observed :
  equiv [RawForest(PreparationView(Independent)).one ~ WrapperForsOneViews.recover :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; call (_ : ={glob Independent}); first by sim.
  call (fors_sign_witness_projection (PreparationView(Independent))); auto; smt().
qed.

lemma wrapper_fors_recovery_eliminated seed0 ht0 tree0 target0 :
  0<=target0<2048 =>
  equiv [WrapperForsOneViews.recover ~ WrapperForsOneViews.direct :
    arg{1}=(seed0,ht0,tree0,target0) /\ ={arg,glob Independent} ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof.
  move=> ht; proc; seq 1 1 : (={seed,ht,tree,target,signed,glob Independent} /\
    seed{1}=seed0 /\ ht{1}=ht0 /\ tree{1}=tree0 /\ target{1}=target0 /\
    rows_width 11 signed{1}.`2 /\ exists d,
      Independent.rawhistory{1}.[fors_leaf_input seed0 ht0 tree0 target0 signed{1}.`1]=Some d /\
      path_recorded Independent.rawhistory{1} (fors_pair seed0 ht0 tree0)
        (node d,0,target0) signed{1}.`2 /\
      (path_value Independent.rawhistory{1} (fors_pair seed0 ht0 tree0)
        (node d,0,target0) signed{1}.`2).`1=signed{1}.`3).
  + call (_ : arg{1}=(seed0,ht0,tree0,target0) /\ ={arg,glob Independent} ==>
      ={res,glob Independent} /\ rows_width 11 res{1}.`2 /\ exists d,
      Independent.rawhistory{1}.[fors_leaf_input seed0 ht0 tree0 target0 res{1}.`1]=Some d /\
      path_recorded Independent.rawhistory{1} (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res{1}.`2 /\
      (path_value Independent.rawhistory{1} (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res{1}.`2).`1=res{1}.`3).
    - conseq (_ : ={arg,glob Independent} ==> ={res,glob Independent})
        (fors_sign_witness_path seed0 ht0 tree0 target0); 1,2:smt().
      by sim.
    auto; smt().
  elim* => d.
  exists* signed{1},Independent.rawhistory{1},Independent.secrethistory{1}; elim* => sig0 h0 s0.
  call{1} (wrapper_fors_recover_total seed0 ht0 tree0 target0 sig0.`1 sig0.`2 d sig0.`3 h0 s0).
  auto; rewrite /rows_width; smt().
qed.

lemma wrapper_fors_one_delayed :
  equiv [WrapperForsOneViews.direct ~ WrapperForsOneViews.late :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof. proc; call wrapper_fors_deferred_secret; auto. qed.

lemma wrapper_fors_delayed_public_plan seed_ref ht_ref tree_ref target_ref :
  0<=target_ref<2048 =>
  equiv [WrapperForsOneViews.late ~ WrapperForsPublicPlan(ConcreteForsLeaf(PreparationView(Independent))).one :
    arg{1}=(seed_ref,ht_ref,tree_ref,target_ref) /\ ={arg,glob Independent} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    res{1}.`2=res{2}.`2 /\ res{1}.`3=res{2}.`1 /\
    fors_private_key ht_ref tree_ref target_ref \in Independent.secrethistory{1} /\
    res{1}.`1=node (oget Independent.secrethistory{1}.[fors_private_key ht_ref tree_ref target_ref])].
proof.
  move=> ht; proc; inline WrapperDeferredFors.sign.
  seq 5 1 : (seed0{1}=seed_ref /\ ht0{1}=ht_ref /\ tree0{1}=tree_ref /\ target0{1}=target_ref /\
    result{1}=built{2} /\ ={glob Independent} /\
    fors_private_key ht_ref tree_ref target_ref \in Independent.secrethistory{1}).
  + call (_ : arg{1}=(seed_ref,ht_ref,tree_ref,target_ref) /\ ={arg,glob Independent} ==>
      ={res,glob Independent} /\ fors_private_key ht_ref tree_ref target_ref \in Independent.secrethistory{1}).
    - conseq (leaf_fors_tree_projection (PreparationView(Independent)))
        (fors_tree_private_path seed_ref ht_ref tree_ref target_ref); 1,2:smt(domE).
    auto.
  inline PreparationView(Independent).fors.
  exists* Independent.secrethistory{1}; elim* => s0.
  wp; call{1} (wrapper_private_entry_total s0 (fors_private_key ht_ref tree_ref target_ref)
    (oget s0.[fors_private_key ht_ref tree_ref target_ref])).
  auto; rewrite /fors_private_key; smt(domE).
qed.
