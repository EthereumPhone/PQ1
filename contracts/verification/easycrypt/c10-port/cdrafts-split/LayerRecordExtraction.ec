(* References may be selected from the final retained history; no extra queries. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawLayer RawSignature.
require import PathReplay RawPathReplay PathInputs LayerPath WotsReferenceRoot.
require import MerkleRootWitness RootCoverage VerifierWotsOpening WotsRecoveryHistory.
require import LayerRecoveryRecord MemoNodeCollision PublicNodeZero NodeCollisionEvents.

lemma recorded_layer_extracts h s seed layer tree index message (signature : layer_signature) root :
  layer_width signature => 0<=index<512 =>
  merkle_root_witness h s seed layer tree root =>
  layer_recovery_record h seed layer tree index message signature root =>
  !public_node_collision h => !public_node_zero h =>
  exists leaf, wots_verifier_opening h s seed layer tree index message leaf (signature.`1,signature.`2).
proof.
  move=> [hs [hc ha]] hi hr [leaf [ht hp]] hn hz.
  have [reference auth [hw [hk hpath]]] := root_reference_at h s seed layer tree root index hr hi.
  have he : leaf=reference.
  + have hl : size leaf=16 by smt(recovery_trace_width).
    have hrl : size reference=16 by move: hk; rewrite /wots_root; smt(node_width).
    have hx := path_leaf_or_input_collision h (merkle_pair seed layer tree) signature.`3 auth
      leaf reference 0 index (merkle_pair_injective seed layer tree) _ _ _ hl hrl _ _ _.
    - smt().
    - smt().
    - smt().
    - move: hp; rewrite /layer_path; smt().
    - move: hpath; rewrite /layer_path; smt().
    - move: hp hpath; rewrite /layer_path; smt().
    smt(path_input_collision_is_public).
  exists reference; apply recovery_trace_opens_reference => //; smt().
qed.
