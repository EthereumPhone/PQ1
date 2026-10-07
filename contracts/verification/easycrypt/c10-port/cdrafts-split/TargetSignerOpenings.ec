(* Bind a newly observed ordinary opening to the successful signature's digest. *)
require import AllCore List FMap.
require import C10RawOracle C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawLayer RawForest RawSigner RoleGrind GrindReturned SignerReturned.
require import ForsPrivateLeaves LeafSignerView TargetByteView TargetOracleSplit.
require import TargetTableProjection TargetOpeningFrames TargetForestOpenings TargetSignerProjection.

lemma target_finish_opening flag target_ht target_tree target_index digest0 :
  hoare [TargetSigning(ObservedTarget(Independent)).finish :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index /\ digest=digest0 ==>
    OriginalTargetState.revealed => flag \/
      forest_opens_input (fors_private_key target_ht target_tree target_index) (hypertree_index digest0) digest0].
proof.
  proc; wp; while (TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    (OriginalTargetState.revealed => flag \/
      forest_opens_input (fors_private_key target_ht target_tree target_index) (hypertree_index digest0) digest0)).
  + wp; exists* OriginalTargetState.revealed; elim* => b.
    call (observed_layer_preserves_opening RawLayer b target_ht target_tree target_index); auto.
  wp; call (forest_sign_opening flag (fors_private_key target_ht target_tree target_index) (hypertree_index digest0) digest0).
  auto.
qed.

lemma target_finish_keeps_entry randomizer0 x0 d0 :
  hoare [TargetSigning(ObservedTarget(Independent)).finish :
    randomizer=randomizer0 /\ Independent.rawhistory.[x0]=Some d0 ==>
    Independent.rawhistory.[x0]=Some d0 /\ (res<>None => (oget res).`1=randomizer0)].
proof.
  conseq observed_finish_projection (finish_keeps_randomizer_entry randomizer0 x0 d0); smt().
qed.

lemma target_grind_entry seed0 root0 message0 :
  hoare [RoleGrind(TargetPrefix(ObservedTarget(Independent))).run :
    seed=seed0 /\ root=root0 /\ message=message0 ==>
    returned_digest_entry Independent.rawhistory seed0 root0 message0 res].
proof.
  conseq observed_grind_projection (grind_returned_entry seed0 root0 message0); smt().
qed.

op signature_opens_input h seed root message (sig : raw_signature) input =
  exists d, h.[hmsg_input seed root (pad sig.`1) message]=Some d /\
    forest_opens_input input (hypertree_index d) d.

lemma target_signer_opening flag target_ht target_tree target_index seed0 root0 message0 :
  hoare [TargetSigning(ObservedTarget(Independent)).sign :
    OriginalTargetState.revealed=flag /\
    TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    seed=seed0 /\ root=root0 /\ message=message0 ==>
    res<>None => OriginalTargetState.revealed => flag \/
      signature_opens_input Independent.rawhistory seed0 root0 message0 (oget res)
        (fors_private_key target_ht target_tree target_index)].
proof.
  proc; seq 1 : (seed=seed0 /\ root=root0 /\ message=message0 /\
    OriginalTargetState.revealed=flag /\
    TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    returned_digest_entry Independent.rawhistory seed0 root0 message0 accepted).
  + call (_ : seed=seed0 /\ root=root0 /\ message=message0 /\
      OriginalTargetState.revealed=flag /\
      TargetConfig.input=fors_private_key target_ht target_tree target_index ==>
      OriginalTargetState.revealed=flag /\
      TargetConfig.input=fors_private_key target_ht target_tree target_index /\
      returned_digest_entry Independent.rawhistory seed0 root0 message0 res).
    - conseq (observed_grind_preserves_opening flag target_ht target_tree target_index)
        (target_grind_entry seed0 root0 message0); smt().
    auto.
  sp 1; if; last by auto.
  exists* accepted; elim* => answer.
  call (_ : digest=(oget answer).`2 /\ randomizer=(oget answer).`1 /\
    OriginalTargetState.revealed=flag /\
    TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    Independent.rawhistory.[hmsg_input seed0 root0 (pad (oget answer).`1) message0]=Some (oget answer).`2 ==>
    Independent.rawhistory.[hmsg_input seed0 root0 (pad (oget answer).`1) message0]=Some (oget answer).`2 /\
    (res<>None => (oget res).`1=(oget answer).`1) /\
    (OriginalTargetState.revealed => flag \/
      forest_opens_input (fors_private_key target_ht target_tree target_index)
        (hypertree_index (oget answer).`2) (oget answer).`2)).
  + conseq (target_finish_opening flag target_ht target_tree target_index (oget answer).`2)
      (target_finish_keeps_entry (oget answer).`1
        (hmsg_input seed0 root0 (pad (oget answer).`1) message0) (oget answer).`2); smt().
  auto; rewrite /returned_digest_entry /signature_opens_input /pad; smt().
qed.

