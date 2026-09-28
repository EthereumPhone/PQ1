(* The actual per-tree signing/recovery call returns its complete recorded root. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest RawSignature.
require import PathReplay RawForsPathReplay PersistentGrind AcceptedContexts ForsOpening ForsOpeningReplay.
require import ForsSignWitness ForsRootWitness ForsRootRecording.

lemma observed_fors_sign_root seed0 ht0 tree0 target0 :
  hoare [ForsSignWitness(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<2048 ==>
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 res.`3].
proof.
  proc; call (fors_tree_records_root seed0 ht0 tree0 target0); wp.
  call (_ : true ==> true); first by trivial.
  auto; smt().
qed.

lemma observed_fors_sign_reference seed0 ht0 tree0 target0 :
  hoare [ForsSignWitness(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<2048 ==>
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 res.`3 /\
    fors_opening Independent.rawhistory seed0 ht0 tree0 target0 res.`1 res.`2 res.`3].
proof.
  conseq (observed_fors_sign_root seed0 ht0 tree0 target0)
    (fors_sign_witness_path seed0 ht0 tree0 target0); rewrite /fors_opening /rows_width; smt().
qed.

lemma raw_fors_sign_reference seed0 ht0 tree0 target0 :
  hoare [RawFors(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<2048 ==>
    exists root, fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 root /\
      fors_opening Independent.rawhistory seed0 ht0 tree0 target0 res.`1 res.`2 root].
proof.
  conseq (fors_sign_witness_projection (PreparationView(Independent)))
    (observed_fors_sign_reference seed0 ht0 tree0 target0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma raw_forest_one_root seed0 ht0 tree0 target0 :
  hoare [RawForest(PreparationView(Independent)).one :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ leaf=target0 /\ 0<=target0<2048 ==>
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 res.`3].
proof.
  proc; seq 1 : (exists reference_root,
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ leaf=target0 /\
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 reference_root /\
    fors_opening Independent.rawhistory seed0 ht0 tree0 target0 sig.`1 sig.`2 reference_root).
  + call (raw_fors_sign_reference seed0 ht0 tree0 target0); auto; smt().
  elim* => reference_root.
  exists* sig,Independent.rawhistory,Independent.secrethistory; elim* => sig0 h0 s0.
  call (fixed_fors_recover seed0 ht0 tree0 target0 sig0.`1 sig0.`2 reference_root s0 h0).
  auto; smt(extends_refl fors_root_witness_extends).
qed.
