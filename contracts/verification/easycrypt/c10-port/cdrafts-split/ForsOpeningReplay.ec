(* The actual FORS recovery replays an earlier retained opening. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import PersistentGrind PathReplay RawForsPathReplay RawForsComparison.
require import ForsOpening ForsComponentHistory.

lemma fors_recover_opening seed0 ht0 tree0 target0 secret0 auth0 root0 :
  hoare [RawFors(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ secret=secret0 /\ auth=auth0 /\
    fors_opening Independent.rawhistory seed0 ht0 tree0 target0 secret0 auth0 root0 ==>
    res=root0].
proof.
  conseq (_ : exists d,
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ secret=secret0 /\ auth=auth0 /\ size auth0=11 /\
    Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 secret0]=Some d /\
    path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0) (node d,0,target0) auth0 /\
    (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0) (node d,0,target0) auth0).`1=root0 ==> res=root0).
  + rewrite /fors_opening; smt().
  elim* => d.
  conseq (fors_recover_recorded_repeat seed0 ht0 tree0 target0 secret0 auth0 d root0); smt().
qed.

lemma fixed_fors_recover seed0 ht0 tree0 target0 secret0 auth0 root0 s0 h0 :
  hoare [RawFors(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ secret=secret0 /\ auth=auth0 /\
    fors_opening h0 seed0 ht0 tree0 target0 secret0 auth0 root0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=root0 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  conseq (fors_recover_opening seed0 ht0 tree0 target0 secret0 auth0 root0)
    (fors_recover_extends RawFors s0 h0); smt(fors_opening_extends).
qed.
