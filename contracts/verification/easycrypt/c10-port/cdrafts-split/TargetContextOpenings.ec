(* Initialized byte context connects nonfailed openings to its persistent log. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import ForsPrivateLeaves RawSigner FullSession ByteSession ExposureLog ClientQueryLog.
require import ReturnedPrivateInputs LeafSessionView TargetOracleSplit TargetByteView.
require import TargetTableProjection TargetOpeningFrames TargetClientOpenings.

lemma observed_context_openings
  (A <: FullClient {-Independent,-OriginalTargetState,-TargetConfig,-FullSession,-FullLimits,
    -KeygenInputs,-ExposureLog,-ClientQueryLog}) target_ht target_tree target_index :
  hoare [TargetQueryContext(A,ObservedTarget(Independent)).run :
    !OriginalTargetState.revealed /\ TargetConfig.input=fors_private_key target_ht target_tree target_index ==>
    res => !FullSession.failed /\
      (OriginalTargetState.revealed => returned_private_input Independent.rawhistory
        FullSession.seed FullSession.root ExposureLog.entries (fors_private_key target_ht target_tree target_index))].
proof.
  proc; seq 1 : (!OriginalTargetState.revealed /\
    TargetConfig.input=fors_private_key target_ht target_tree target_index).
  + call (observed_keygen_preserves_opening false target_ht target_tree target_index); auto; smt().
  exists* inputs; elim* => key.
  call (observed_driver_openings A target_ht target_tree target_index key.`3 key.`4); auto; smt().
qed.

lemma observed_byte_candidates_unopened
  (A <: ByteClient {-Independent,-OriginalTargetState,-TargetConfig,-FullSession,-FullLimits,
    -KeygenInputs,-ExposureLog,-ClientQueryLog}) target_ht target_tree target_index :
  hoare [TargetByteCandidates(A,ObservedTarget(Independent)).run :
    !OriginalTargetState.revealed /\ TargetConfig.input=fors_private_key target_ht target_tree target_index ==>
    0<size res =>
      !returned_private_input Independent.rawhistory FullSession.seed FullSession.root ExposureLog.entries
        (fors_private_key target_ht target_tree target_index) => !OriginalTargetState.revealed].
proof.
  proc; wp; call (observed_context_openings (ByteLift(A)) target_ht target_tree target_index).
  auto; smt().
qed.
