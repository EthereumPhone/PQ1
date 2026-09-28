(* Actual memoized Merkle recovery records and evaluates its authentication path. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle.
require import PathReplay PathOracle.

op merkle_pair (seed : raw_input) (layer tree height parent : int)
  (left right : raw_input) =
  seed ++ address layer tree 2 0 0 height parent ++ pad left ++ pad right.

lemma merkle_recover_recorded seed0 layer0 tree0 leaf0 index0 auth0 :
  hoare[RawMerkle(PreparationView(Independent)).recover :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\
    leaf = leaf0 /\ index = index0 /\ auth = auth0 /\ size auth0 = 9 ==>
    path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (leaf0,0,index0) auth0 /\
    res = (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (leaf0,0,index0) auth0).`1].
proof.
  proc; while (seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ auth = auth0 /\
    0 <= h <= 9 /\ size auth0 = 9 /\
    path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (leaf0,0,index0) (take h auth0) /\
    path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (leaf0,0,index0) (take h auth0) = (current,h,idx)).
  + wp; exists* h, current, idx; elim* => h0 current0 idx0.
    call (hash_preserves_path (merkle_pair seed0 layer0 tree0) (leaf0,0,index0)
      (take h0 auth0) (current0,h0,idx0)
      (path_input (merkle_pair seed0 layer0 tree0) (current0,h0,idx0)
        (nth (nseq 16 0) auth0 h0))).
    auto; rewrite /path_input /merkle_pair /=;
      smt(path_recorded_step take_nth).
  auto; rewrite /path_value /= take0; smt(take_size).
qed.
