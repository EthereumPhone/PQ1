(* The real per-tree signer/recovery call retains the opening it returned. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest RawSignature RawTreeWidths.
require import PathReplay RawForsPathReplay ForsOpening ForsComponentHistory PersistentGrind BuilderTotality.

lemma forest_one_recorded seed0 ht0 tree0 target0 :
  hoare [RawForest(PreparationView(Independent)).one :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ leaf=target0 ==>
    fors_opening Independent.rawhistory seed0 ht0 tree0 target0 res.`1 res.`2 res.`3].
proof.
  proc; seq 1 : (seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ leaf=target0 /\ size sig.`2=11).
  + call (raw_fors_sign_width (PreparationView(Independent)) independent_hash_ll preparation_fors_ll).
    auto; rewrite /rows_width; smt().
  exists* sig; elim* => sig0.
  call (fors_recover_recorded seed0 ht0 tree0 target0 sig0.`1 sig0.`2).
  auto; rewrite /fors_opening; smt().
qed.

lemma forest_one_recorded_extends seed0 ht0 tree0 target0 s0 h0 :
  hoare [RawForest(PreparationView(Independent)).one :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ leaf=target0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    fors_opening Independent.rawhistory seed0 ht0 tree0 target0 res.`1 res.`2 res.`3 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  conseq (forest_one_recorded seed0 ht0 tree0 target0)
    (fors_one_extends RawForest s0 h0); smt().
qed.
