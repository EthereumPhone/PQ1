(* Exact finite state and cost composition for signer layers. The trace
   contains only the executed prefix and preserves every intermediate map. *)
require import AllCore List IntDiv FMap.
require import C10RawOracle C10RawGrind C10FixedBackend C10FixedCallerBridge.
require import RawForest.
require import C10FunctionalSignerValue C10FunctionalLayerSign C10FunctionalForestSign.
require import C10FunctionalBuildHistory C10FunctionalMerkleBuildHistory.
require import C10FunctionalVerifierValue.

op functional_signer_step_cost f key seed d shuffle i =
  functional_layer_sign_cost f key seed i
    (functional_verifier_index (hypertree_index d) i %/ 512)
    (functional_verifier_index (hypertree_index d) i %% 512)
    (functional_signer_current f key seed d i) shuffle.
op functional_signer_layers_cost f key seed d shuffle n =
  if n = 0 then 0 else functional_signer_step_cost f key seed d shuffle 0 +
    (if n = 1 then 0 else functional_signer_step_cost f key seed d shuffle 1).
op functional_signer_step_state f initial final key seed d shuffle i =
  let idx = functional_verifier_index (hypertree_index d) i in
  exists built, functional_history_exact f initial built
    (functional_tree_queried (functional_merkle_build_queries f key seed i (idx %/ 512)) 9) /\
    final = functional_layer_sign_history f built key seed i (idx %/ 512) (idx %% 512)
      (functional_signer_current f key seed d i) shuffle.
op functional_signer_layers_state f initial final key seed d shuffle n =
  exists (histories : int -> (raw_input,digest) fmap),
    histories 0 = initial /\ histories n = final /\
    forall i, 0 <= i < n =>
      functional_signer_step_state f (histories i) (histories (i+1)) key seed d shuffle i.
op functional_finish_cost f key seed d shuffle =
  functional_forest_initial_cost f shuffle + 80017 +
    functional_signer_layers_cost f key seed d shuffle (functional_signer_iterations f key seed d).
op functional_finish_state f initial final key seed d shuffle =
  exists forest, functional_forest_sign_state f initial forest key seed (hypertree_index d) d shuffle /\
    functional_signer_layers_state f forest final key seed d shuffle (functional_signer_iterations f key seed d).

lemma functional_signer_layers_state_zero f h key seed d shuffle :
  functional_signer_layers_state f h h key seed d shuffle 0.
proof.
  rewrite /functional_signer_layers_state; exists (fun i => h); smt().
qed.

lemma functional_signer_layers_state_step f h mid final key seed d shuffle n : 0 <= n =>
  functional_signer_layers_state f h mid key seed d shuffle n =>
  functional_signer_step_state f mid final key seed d shuffle n =>
  functional_signer_layers_state f h final key seed d shuffle (n+1).
proof.
  move=> hn; rewrite /functional_signer_layers_state => [[histories [hzero [hend hsteps]]] hnew].
  exists (fun i => if i = n+1 then final else histories i); split; first smt().
  split; first smt().
  move=> i hi; case (i = n) => he; smt().
qed.

lemma functional_signer_layers_cost_step f key seed d shuffle n : 0 <= n < 2 =>
  functional_signer_layers_cost f key seed d shuffle (n+1) =
    functional_signer_layers_cost f key seed d shuffle n + functional_signer_step_cost f key seed d shuffle n.
proof.
  move=> hn; have hc : n = 0 \/ n = 1 by smt().
  case: hc => ->; by rewrite /functional_signer_layers_cost /=.
qed.

lemma functional_signer_initial f h key seed d shuffle :
  functional_signer_current f key seed d 0 = (functional_signer_forest f key seed d).`3 /\
  functional_signer_layers f key seed d 0 = [] /\ functional_signer_ok f key seed d 0 /\
  functional_verifier_index (hypertree_index d) 0 = hypertree_index d /\
  functional_signer_layers_cost f key seed d shuffle 0 = 0 /\
  functional_signer_layers_state f h h key seed d shuffle 0.
proof.
  by rewrite /functional_signer_current /functional_signer_layers /functional_signer_ok
    /functional_verifier_index /functional_signer_layers_cost /= functional_signer_layers_state_zero.
qed.

lemma functional_signer_complete f h forest final key seed randomizer d shuffle i :
  size d = 256 => 0 <= i <= 2 =>
  (i = 2 \/ !functional_signer_ok f key seed d i) =>
  (i = 2 => functional_signer_layer0 f key seed d <> None) =>
  functional_forest_sign_state f h forest key seed (hypertree_index d) d shuffle =>
  functional_signer_layers_state f forest final key seed d shuffle i =>
  (if functional_signer_ok f key seed d i then Some
    (randomizer,(functional_signer_forest f key seed d).`1,(functional_signer_forest f key seed d).`2,
      functional_signer_layers f key seed d i) else None) =
    paired_finish_result (C10FunctionalWotsValue.interpreted_backend f) key seed randomizer (C10Bytes.bits_to_bytes d) /\
  functional_forest_initial_cost f shuffle + 80017 + functional_signer_layers_cost f key seed d shuffle i =
    functional_finish_cost f key seed d shuffle /\
  functional_finish_state f h final key seed d shuffle.
proof.
  move=> hd hi he hp hf hs.
  have [hi' hr] := functional_signer_finish_value f key seed randomizer d i hd hi he hp.
  rewrite hr /functional_finish_cost /functional_finish_state hi' /=; smt().
qed.
