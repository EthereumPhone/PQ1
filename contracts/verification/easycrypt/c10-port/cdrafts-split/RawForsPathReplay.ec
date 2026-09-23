(* Actual FORS recovery records both its leaf hash and authentication path. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import PathReplay PathOracle GrindReturned.

op fors_leaf_input (seed : raw_input) (ht tree target : int) (secret : raw_input) =
  seed ++ address 0 ht 3 tree 0 0 target ++ pad secret.
op fors_pair (seed : raw_input) (ht tree height parent : int)
  (left right : raw_input) =
  seed ++ address 0 ht 3 tree 0 height parent ++ pad left ++ pad right.

lemma fors_recover_recorded seed0 ht0 tree0 target0 secret0 auth0 :
  hoare[RawFors(PreparationView(Independent)).recover :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    secret = secret0 /\ auth = auth0 /\ size auth0 = 11 ==>
    exists d,
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 secret0] = Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) auth0 /\
      res = (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) auth0).`1].
proof.
  proc; seq 1 : (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    auth = auth0 /\ size auth0 = 11 /\
    Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 secret0] = Some d).
  + call (independent_hash_records_entry (fors_leaf_input seed0 ht0 tree0 target0 secret0)).
    auto; rewrite /fors_leaf_input; smt().
  exists* d; elim* => d0.
  while (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ auth = auth0 /\
    0 <= h <= 11 /\ size auth0 = 11 /\
    Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 secret0] = Some d0 /\
    path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node d0,0,target0) (take h auth0) /\
    path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node d0,0,target0) (take h auth0) = (current,h,idx)).
  + wp; exists* h, current, idx; elim* => h0 current0 idx0.
    call (hash_preserves_path_entry (fors_pair seed0 ht0 tree0) (node d0,0,target0)
      (take h0 auth0) (current0,h0,idx0)
      (path_input (fors_pair seed0 ht0 tree0) (current0,h0,idx0)
        (nth (nseq 16 0) auth0 h0))
      (fors_leaf_input seed0 ht0 tree0 target0 secret0) d0).
    auto; rewrite /path_input /fors_pair /=;
      smt(path_recorded_step take_nth).
  auto; rewrite /path_value /= take0; smt(take_size).
qed.
