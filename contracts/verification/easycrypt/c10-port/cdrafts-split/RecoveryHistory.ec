(* Actual recovery procedures use only public hashes and preserve earlier
   path witnesses. No private history is exposed through these interfaces. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import PathReplay PathOracle.

module type MerkleRecovery (O : PreparationOracle) = {
  proc recover(seed : raw_input, layer tree : int, leaf : raw_input,
    index : int, auth : raw_input list) : raw_input { O.hash }
}.

module type ForsRecovery (O : PreparationOracle) = {
  proc recover(seed : raw_input, ht tree target : int, secret : raw_input,
    auth : raw_input list) : raw_input { O.hash }
}.

lemma merkle_recovery_keeps_path_root (R <: MerkleRecovery {-Independent})
  f st auth root0 :
  hoare[R(PreparationView(Independent)).recover :
    path_recorded Independent.rawhistory f st auth /\
    (path_value Independent.rawhistory f st auth).`1 = root0 ==>
    path_recorded Independent.rawhistory f st auth /\
    (path_value Independent.rawhistory f st auth).`1 = root0].
proof.
  proc (path_recorded Independent.rawhistory f st auth /\
    (path_value Independent.rawhistory f st auth).`1 = root0) => //.
  exact (hash_keeps_path_root f st auth root0).
qed.

lemma fors_recovery_keeps_path_root_entry (R <: ForsRecovery {-Independent})
  f st auth root0 entry d0 :
  hoare[R(PreparationView(Independent)).recover :
    path_recorded Independent.rawhistory f st auth /\
    (path_value Independent.rawhistory f st auth).`1 = root0 /\
    Independent.rawhistory.[entry] = Some d0 ==>
    path_recorded Independent.rawhistory f st auth /\
    (path_value Independent.rawhistory f st auth).`1 = root0 /\
    Independent.rawhistory.[entry] = Some d0].
proof.
  proc (path_recorded Independent.rawhistory f st auth /\
    (path_value Independent.rawhistory f st auth).`1 = root0 /\
    Independent.rawhistory.[entry] = Some d0) => //.
  exact (hash_keeps_path_root_entry f st auth root0 entry d0).
qed.
