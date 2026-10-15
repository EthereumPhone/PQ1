(* Candidate counts of the existing redacted target adapter. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen LeafOpeningBound TargetOracleSplit TargetByteView TargetAdapterCost.
require import LeafCandidateCount.

lemma leaf_target_derive_bound q :
  hoare[IdealPrefix.derive : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q].
proof.
  proc; if.
  + wp; call (_ : true ==> true); first by trivial.
    auto.
  call (_ : true ==> true); first by trivial.
  auto.
qed.
lemma leaf_target_wots_bound q :
  hoare[IdealPreparation.wots : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q].
proof. proc; call (leaf_target_derive_bound q); auto. qed.
