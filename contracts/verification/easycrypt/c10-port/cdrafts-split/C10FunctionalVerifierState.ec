(* Exact histories and query costs for both verifier layers. Each history
   starts with arbitrary backend-consistent state; repeated queries remain. *)
require import AllCore List IntDiv FMap.
require import C10Bytes C10RawOracle C10RawGrind RawSigner RawLayer RawForest.
require import C10FixedBackend C10FixedCallerBridge C10FunctionalWotsValue.
require import C10FunctionalForestRecover C10FunctionalLayerRecover C10FunctionalVerifierValue.

op functional_verifier_first_history f h seed d (sig : raw_signature) =
  functional_layer_recovery_history f h seed 0 (hypertree_index d %/ 512) (hypertree_index d %% 512)
    (functional_verifier_root f seed d sig 0) (functional_verifier_layer sig 0).
op functional_verifier_layer_history f h seed d (sig : raw_signature) i =
  if i = 0 then h else if i = 1 then functional_verifier_first_history f h seed d sig else
  functional_layer_recovery_history f (functional_verifier_first_history f h seed d sig)
    seed 1 (hypertree_index d %/ 512 %/ 512) (hypertree_index d %/ 512 %% 512)
    (functional_verifier_root f seed d sig 1) (functional_verifier_layer sig 1).
op functional_verifier_first_cost f seed d (sig : raw_signature) =
  functional_layer_recovery_cost f seed 0 (hypertree_index d %/ 512) (hypertree_index d %% 512)
    (functional_verifier_root f seed d sig 0) (functional_verifier_layer sig 0).
op functional_verifier_layer_cost f seed d (sig : raw_signature) i =
  if i = 0 then 0 else if i = 1 then functional_verifier_first_cost f seed d sig else
  functional_verifier_first_cost f seed d sig +
    functional_layer_recovery_cost f seed 1 (hypertree_index d %/ 512 %/ 512) (hypertree_index d %/ 512 %% 512)
      (functional_verifier_root f seed d sig 1) (functional_verifier_layer sig 1).

lemma functional_verifier_history_step f h seed d sig i : 0 <= i < 2 =>
  let idx = functional_verifier_index (hypertree_index d) i in
  functional_layer_recovery_history f (functional_verifier_layer_history f h seed d sig i)
    seed i (idx %/ 512) (idx %% 512) (functional_verifier_root f seed d sig i)
    (functional_verifier_layer sig i) = functional_verifier_layer_history f h seed d sig (i+1).
proof.
  move=> hi; have hc : i = 0 \/ i = 1 by smt().
  case: hc => ->; by rewrite /functional_verifier_index /functional_verifier_layer_history
    /functional_verifier_first_history /=.
qed.

lemma functional_verifier_cost_step f seed d sig i : 0 <= i < 2 =>
  let idx = functional_verifier_index (hypertree_index d) i in
  functional_verifier_layer_cost f seed d sig i +
    functional_layer_recovery_cost f seed i (idx %/ 512) (idx %% 512)
      (functional_verifier_root f seed d sig i) (functional_verifier_layer sig i) =
    functional_verifier_layer_cost f seed d sig (i+1).
proof.
  move=> hi; have hc : i = 0 \/ i = 1 by smt().
  case: hc => ->; by rewrite /functional_verifier_index /functional_verifier_layer_cost
    /functional_verifier_first_cost /=.
qed.

op functional_verifier_forest_history f h seed root message (sig : raw_signature) =
  let q = functional_verifier_query seed root message sig in
  functional_forest_recovery_history f (remember h q (f q)) seed (hypertree_index (f q)) (f q) sig.`2 sig.`3.
op functional_verifier_history f h seed root message (sig : raw_signature) =
  let q = functional_verifier_query seed root message sig in
  if accept_digest (f q) then
    functional_verifier_layer_history f (functional_verifier_forest_history f h seed root message sig)
      seed (f q) sig 2
  else remember h q (f q).
op functional_verifier_cost f seed root message (sig : raw_signature) =
  let q = functional_verifier_query seed root message sig in
  if accept_digest (f q) then 147 + functional_verifier_layer_cost f seed (f q) sig 2 else 1.

