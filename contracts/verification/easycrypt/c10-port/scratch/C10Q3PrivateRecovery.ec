require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import PathReplay PathOracle PathCollision PathInputs RawPathReplay RawForsPathReplay RecoveryHistory ForsLeafInputs RawPathComparison RawForsComparison.
lemma without_private_restriction (R <: MerkleRecovery)
  f st auth root0 :
  hoare[R(PreparationView(Independent)).recover :
    path_recorded Independent.rawhistory f st auth /\
    (path_value Independent.rawhistory f st auth).`1 = root0 ==>
    path_recorded Independent.rawhistory f st auth /\
    (path_value Independent.rawhistory f st auth).`1 = root0].
proof. exact (merkle_recovery_keeps_path_root R f st auth root0). qed.
