(* The actual verifier's forest paths, special last hash and compression. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest.
require import PersistentGrind AcceptedContexts ForsOpening RawForsPathReplay ForsComponentHistory.
require import ForestOpenings ForestWitness ForestOpening ForestOracle.

op forest_recovery_prefix h seed ht digest secrets auths roots t =
  size roots=t /\ forall i, 0<=i<t =>
    fors_opening h seed ht i (forest_index digest i)
      (nth (nseq 16 0) secrets i) (nth [] auths i) (nth (nseq 16 0) roots i).

lemma forest_recovery_prefix_extends h h' seed ht digest secrets auths roots t :
  extends h h' => forest_recovery_prefix h seed ht digest secrets auths roots t =>
  forest_recovery_prefix h' seed ht digest secrets auths roots t.
proof. rewrite /forest_recovery_prefix; smt(fors_opening_extends). qed.

lemma forest_recovery_prefix_step h seed ht digest secrets auths roots t root :
  0<=t => forest_recovery_prefix h seed ht digest secrets auths roots t =>
  fors_opening h seed ht t (forest_index digest t)
    (nth (nseq 16 0) secrets t) (nth [] auths t) root =>
  forest_recovery_prefix h seed ht digest secrets auths (rcons roots root) (t+1).
proof.
  move=> hnonneg [hs hp] hr; rewrite /forest_recovery_prefix size_rcons hs; split; first smt().
  move=> i hi; rewrite nth_rcons hs; smt().
qed.

lemma forest_recovery_prefix_finish h seed ht digest secrets auths roots d :
  size secrets=13 => size auths=12 =>
  forest_recovery_prefix h seed ht digest secrets auths roots 12 =>
  h.[forest_special_input seed ht (nth (nseq 16 0) secrets 12)]=Some d =>
  forest_witness h seed ht digest secrets auths (rcons roots (node d)).
proof.
  rewrite /forest_recovery_prefix /forest_witness /forest_openings.
  move=> hse hau [hro hp] hd; rewrite size_rcons hro; split.
  + split; first exact hse.
    split; first exact hau.
    split; first smt().
    move=> i hi; rewrite nth_rcons hro; smt(mem_range).
  exists d; rewrite nth_rcons hro /=; smt().
qed.

lemma fors_recovery_opening_history seed0 ht0 tree0 target0 secret0 auth0 s0 h0 :
  hoare [RawFors(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ secret=secret0 /\ auth=auth0 /\
    size auth0=11 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    fors_opening Independent.rawhistory seed0 ht0 tree0 target0 secret0 auth0 res /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  conseq (fors_recover_recorded seed0 ht0 tree0 target0 secret0 auth0)
    (fors_recover_extends RawFors s0 h0); rewrite /fors_opening; smt().
qed.

lemma hash_records_forest_prefix seed0 ht0 digest0 secrets0 auths0 roots0 t0 x0 :
  hoare [Independent.hash :
    forest_recovery_prefix Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots0 t0 /\ x=x0 ==>
    forest_recovery_prefix Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots0 t0 /\
    Independent.rawhistory.[x0]=Some res].
proof. proc; sp 1; if; auto; smt(forest_recovery_prefix_extends extends_insert get_set_sameE domE). qed.

lemma raw_forest_recovery_recorded seed0 ht0 digest0 secrets0 auths0 :
  hoare [RawForest(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    size secrets0=13 /\ size auths0=12 /\ all (fun p => size p=11) auths0 ==>
    forest_opening Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 res].
proof.
  proc; seq 3 : (seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    size secrets0=13 /\ size auths0=12 /\
    forest_recovery_prefix Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots 12).
  + while (seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
      size secrets0=13 /\ size auths0=12 /\ all (fun p => size p=11) auths0 /\ 0<=t<=12 /\
      forest_recovery_prefix Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots t).
    - exists* t,roots,Independent.rawhistory,Independent.secrethistory; elim* => t0 roots0 h0 s0.
      wp; call (fors_recovery_opening_history seed0 ht0 t0 (forest_index digest0 t0)
        (nth (nseq 16 0) secrets0 t0) (nth [] auths0 t0) s0 h0).
      auto; smt(extends_refl forest_recovery_prefix_extends forest_recovery_prefix_step allP mem_nth).
    auto; rewrite /forest_recovery_prefix /=; smt().
  exists* roots; elim* => roots0.
  seq 2 : (seed=seed0 /\ ht=ht0 /\
    forest_witness Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots).
  + wp; call (hash_records_forest_prefix seed0 ht0 digest0 secrets0 auths0 roots0 12
      (forest_special_input seed0 ht0 (nth (nseq 16 0) secrets0 12))).
    auto; rewrite /forest_special_input /fors_leaf_input; smt(forest_recovery_prefix_finish).
  exists* roots; elim* => roots1.
  call (hash_records_forest_witness seed0 ht0 digest0 secrets0 auths0 roots1 (forest_compress_input seed0 ht0 roots1)).
  auto; rewrite /forest_compress_input /forest_opening; smt().
qed.
