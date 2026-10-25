(* A completed honest FORS path can be recovered without changing either
   oracle table. Public-query logging still occurs; it is not erased by this
   theorem and remains covered by the original wrapper cost bound. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import PathReplay RawForsPathReplay RawChainCached BuilderTotality.

lemma wrapper_path_recorded_cat h f st before after :
  path_recorded h f st (before++after) =
  (path_recorded h f st before /\ path_recorded h f (path_value h f st before) after).
proof.
  elim: before st => [st | x xs ih st].
  + by rewrite /path_value /=.
  rewrite /path_recorded /= /path_value /=.
  rewrite -/(path_value h f (path_step h f st x) xs) ih; smt().
qed.

lemma wrapper_path_recorded_next h f st auth i :
  0<=i<size auth => path_recorded h f st auth =>
  exists d,
    h.[path_input f (path_value h f st (take i auth)) (nth (nseq 16 0) auth i)]=Some d /\
    path_value h f st (take (i+1) auth)=
      (node d,(path_value h f st (take i auth)).`2+1,(path_value h f st (take i auth)).`3 %/ 2).
proof.
  move=> hi hr.
  have hp : path_recorded h f (path_value h f st (take i auth)) (drop i auth).
  + have he := wrapper_path_recorded_cat h f st (take i auth) (drop i auth).
    rewrite cat_take_drop in he; smt().
  rewrite (drop_nth (nseq 16 0) i auth hi) /path_recorded /= in hp.
  exists (oget h.[path_input f (path_value h f st (take i auth)) (nth (nseq 16 0) auth i)]).
  split; first smt(domE).
  by rewrite (take_nth (nseq 16 0) i auth hi) path_value_rcons /path_step.
qed.

lemma wrapper_fors_recover_tables seed0 ht0 tree0 target0 secret0 auth0 d0 h0 :
  hoare [RawFors(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ secret=secret0 /\ auth=auth0 /\ size auth0=11 /\
    Independent.rawhistory=h0 /\ h0.[fors_leaf_input seed0 ht0 tree0 target0 secret0]=Some d0 /\
    path_recorded h0 (fors_pair seed0 ht0 tree0) (node d0,0,target0) auth0 ==>
    Independent.rawhistory=h0 /\
    res=(path_value h0 (fors_pair seed0 ht0 tree0) (node d0,0,target0) auth0).`1].
proof.
  proc; seq 1 : (seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ auth=auth0 /\ size auth0=11 /\
    Independent.rawhistory=h0 /\ d=d0 /\
    path_recorded h0 (fors_pair seed0 ht0 tree0) (node d0,0,target0) auth0).
  + call (hash_existing_entry h0 (fors_leaf_input seed0 ht0 tree0 target0 secret0) d0).
    auto; rewrite /fors_leaf_input; smt().
  while (seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ auth=auth0 /\ size auth0=11 /\
    0<=h<=11 /\ Independent.rawhistory=h0 /\
    path_recorded h0 (fors_pair seed0 ht0 tree0) (node d0,0,target0) auth0 /\
    path_value h0 (fors_pair seed0 ht0 tree0) (node d0,0,target0) (take h auth0)=(current,h,idx)).
  + exists* h,current,idx; elim* => k current0 idx0.
    wp; call (hash_existing_entry h0
      (path_input (fors_pair seed0 ht0 tree0) (current0,k,idx0) (nth (nseq 16 0) auth0 k))
      (oget h0.[path_input (fors_pair seed0 ht0 tree0) (current0,k,idx0) (nth (nseq 16 0) auth0 k)])).
    auto; rewrite /path_input /fors_pair /=; smt(wrapper_path_recorded_next).
  auto; rewrite /path_value /= take0; smt(take_size).
qed.

lemma wrapper_fors_recover_total seed0 ht0 tree0 target0 secret0 auth0 d0 root0 h0 s0 :
  phoare [RawFors(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ secret=secret0 /\ auth=auth0 /\ size auth0=11 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    h0.[fors_leaf_input seed0 ht0 tree0 target0 secret0]=Some d0 /\
    path_recorded h0 (fors_pair seed0 ht0 tree0) (node d0,0,target0) auth0 /\
    (path_value h0 (fors_pair seed0 ht0 tree0) (node d0,0,target0) auth0).`1=root0 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ res=root0] = 1%r.
proof.
  conseq fors_independent_recover_ll
    (wrapper_fors_recover_tables seed0 ht0 tree0 target0 secret0 auth0 d0 h0); smt().
qed.
