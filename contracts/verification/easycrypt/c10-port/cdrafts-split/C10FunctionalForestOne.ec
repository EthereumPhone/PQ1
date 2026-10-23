(* One actual forest row: selected secret, complete tree construction and
   recovery, with exact final-map membership and 6156 calls. *)
require import AllCore List FMap.
require import C10RawOracle RawForest KeygenPrefixes C10Representation.
require import C10TreeCallerBridge C10OuterCallerBridge C10FixedBackend C10FixedCallerBridge.
require import C10FunctionalWots C10FunctionalWotsValue C10FunctionalTreeValue.
require import C10FunctionalForsRecovery C10FunctionalBuildHistory C10FunctionalForsBuildHistory.
require import C10FunctionalCallerState.

lemma functional_history_compose f initial middle final prior later :
  functional_history_exact f initial middle prior =>
  functional_history_exact f middle final later =>
  functional_history_exact f initial final (fun x => prior x \/ later x).
proof. rewrite /functional_history_exact; smt(). qed.

op functional_forest_one_secret f key ht tree target =
  fors_secret_value (interpreted_backend f) key ht tree target.
op functional_forest_one_path f key seed ht tree target =
  fors_auth_values (interpreted_backend f) seed key ht tree target.
op functional_forest_one_root f key seed ht tree target =
  fors_recover_value (interpreted_backend f) seed ht tree target
    (functional_forest_one_secret f key ht tree target)
    (functional_forest_one_path f key seed ht tree target).
op functional_forest_one_recovery_queries f key seed ht tree target =
  functional_fors_leaf_query seed ht tree target (functional_forest_one_secret f key ht tree target) ::
  mkseq (functional_tree_query f seed 0 ht 3 tree
    (fors_leaf_value (interpreted_backend f) seed ht tree target
      (functional_forest_one_secret f key ht tree target)) target
    (functional_forest_one_path f key seed ht tree target)) 11.
op functional_forest_one_queried f key seed ht tree target x =
  x = fors_private_preimage key ht tree target \/
  functional_tree_queried (functional_fors_build_queries f key seed ht tree) 11 x \/
  x \in functional_forest_one_recovery_queries f key seed ht tree target.

lemma functional_forest_one_history f initial built key seed ht tree target :
  backend_consistent initial f =>
  functional_history_exact f
    (remember initial (fors_private_preimage key ht tree target) (f (fors_private_preimage key ht tree target)))
    built (functional_tree_queried (functional_fors_build_queries f key seed ht tree) 11) =>
  functional_history_exact f initial
    (functional_fors_recovery_history f built seed ht tree target
      (functional_forest_one_secret f key ht tree target)
      (functional_forest_one_path f key seed ht tree target) 11)
    (functional_forest_one_queried f key seed ht tree target).
proof.
  move=> hc hb.
  have hr := functional_history_remember f initial initial (fun _ => false)
    (fors_private_preimage key ht tree target) hc (functional_history_empty f initial).
  have hm := functional_history_compose f initial _ built _ _ hr hb.
  have hq := functional_history_queries f initial built _
    (functional_forest_one_recovery_queries f key seed ht tree target) hc hm.
  move: hq; rewrite functional_fors_recovery_history_order
    /functional_forest_one_recovery_queries /functional_forest_one_queried /functional_history_exact; smt().
qed.

lemma fixed_functional_forest_one f h c key0 seed0 ht0 tree0 target0 :
  hoare[CommonInputForest(FixedPrefix).one :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ leaf = target0 /\
    fors_fields ht0 tree0 /\ 0 <= target0 < 2^32 /\ backend_width f /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = (functional_forest_one_secret f key0 ht0 tree0 target0,
      functional_forest_one_path f key0 seed0 ht0 tree0 target0,
      functional_forest_one_root f key0 seed0 ht0 tree0 target0) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    functional_history_exact f h FixedBackend.history
      (functional_forest_one_queried f key0 seed0 ht0 tree0 target0) /\
    FixedBackend.calls = c+6156].
proof.
  proc; seq 1 : (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ leaf = target0 /\
    sig = fors_sign_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\ backend_width f /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    backend_consistent h f /\ FixedBackend.calls = c+6144 /\
    functional_history_exact f
      (remember h (fors_private_preimage key0 ht0 tree0 target0) (f (fors_private_preimage key0 ht0 tree0 target0)))
      FixedBackend.history (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11)).
  + call (common_functional_fors_sign f h c key0 seed0 ht0 tree0 target0); auto.
  exists* FixedBackend.history; elim* => built0.
  call (fixed_functional_fors f built0 (c+6144) key0 seed0 ht0 tree0 target0
    (functional_forest_one_secret f key0 ht0 tree0 target0)
    (functional_forest_one_path f key0 seed0 ht0 tree0 target0)).
  auto => />; rewrite /fors_sign_values /functional_forest_one_secret /functional_forest_one_path
    /functional_forest_one_root; smt(functional_forest_one_history).
qed.
