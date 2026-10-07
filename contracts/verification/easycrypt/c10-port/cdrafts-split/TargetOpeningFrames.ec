(* Non-FORS derivations and internal commitments do not open the selected value. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawFors RawLayer RawForest RawSigner RoleGrind.
require import ForsPrivateLeaves ForsInputSeparation ForsLeafView TargetByteView TargetOracleSplit.
require import TargetTableProjection SignerComponentHistory VerifierHistory.

lemma observed_derive_not_target flag target :
  hoare [ObservedTarget(Independent).derive :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=target /\ tail<>target ==>
    OriginalTargetState.revealed=flag /\ TargetConfig.input=target].
proof.
  proc; wp; call (_ : true ==> true); first by trivial.
  auto; smt().
qed.
lemma observed_wots_not_fors flag target_ht target_tree target_index :
  hoare [PreparationView(TargetPrefix(ObservedTarget(Independent))).wots :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index ==>
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index].
proof.
  proc; call (observed_derive_not_target flag (fors_private_key target_ht target_tree target_index));
    auto; smt(fors_wots_inputs_disjoint).
qed.
lemma observed_layer_preserves_opening
  (S <: LayerSigning {-Independent,-OriginalTargetState,-TargetConfig}) flag target_ht target_tree target_index :
  hoare [S(PreparationView(TargetPrefix(ObservedTarget(Independent)))).sign :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index ==>
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index].
proof.
  proc (OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index) => //.
  + proc; sp 1; if; auto.
  exact (observed_wots_not_fors flag target_ht target_tree target_index).
qed.
module type WotsRoot (O : PreparationOracle) = {
  proc root(seed : raw_input, layer tree : int) : raw_input {O.hash,O.wots}
}.
lemma observed_root_preserves_opening
  (S <: WotsRoot {-Independent,-OriginalTargetState,-TargetConfig}) flag target_ht target_tree target_index :
  hoare [S(PreparationView(TargetPrefix(ObservedTarget(Independent)))).root :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index ==>
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index].
proof.
  proc (OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index) => //.
  + proc; sp 1; if; auto.
  exact (observed_wots_not_fors flag target_ht target_tree target_index).
qed.
lemma observed_keygen_preserves_opening flag target_ht target_tree target_index :
  hoare [KeygenPreparation(PreparationView(TargetPrefix(ObservedTarget(Independent)))).run :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index ==>
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index].
proof. proc; call (observed_root_preserves_opening RawKeygen flag target_ht target_tree target_index); auto. qed.
lemma observed_grind_preserves_opening flag target_ht target_tree target_index :
  hoare [RoleGrind(TargetPrefix(ObservedTarget(Independent))).run :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index ==>
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index].
proof.
  proc; while (OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index).
  + wp; call (_ : true ==> true); first by trivial.
    wp; call (observed_derive_not_target flag (fors_private_key target_ht target_tree target_index)).
    auto; rewrite /r_tail; smt(fors_r_inputs_disjoint).
  auto.
qed.
lemma observed_verifier_preserves_opening
  (V <: PublicVerifier {-Independent,-OriginalTargetState,-TargetConfig}) flag :
  hoare [V(TargetPrefix(ObservedTarget(Independent))).verify :
    OriginalTargetState.revealed=flag ==> OriginalTargetState.revealed=flag].
proof.
  proc (OriginalTargetState.revealed=flag) => //.
  proc; sp 1; if; auto.
qed.
