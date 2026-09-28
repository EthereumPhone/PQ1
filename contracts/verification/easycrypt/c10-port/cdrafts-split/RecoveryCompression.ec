(* Fixed-width compression rows identify every endpoint of a matching WOTS key. *)
require import AllCore List FMap BitEncoding RadixEncoding.
require import C10RawOracle RawKeygen LinearChain WotsReference WotsLeafReference.
require import WotsRecoveryTrace LinearCollision MemoNodeCollision WotsReferenceRoot.
import BitChunking.

lemma padded_rows_injective (f g : int -> raw_input) n :
  (forall i, 0<=i<n => size (f i)=16 /\ size (g i)=16) =>
  flatten (map (fun i => pad (f i)) (range 0 n)) =
    flatten (map (fun i => pad (g i)) (range 0 n)) =>
  forall i, 0<=i<n => f i=g i.
proof.
  move=> hw he.
  have hf : all (fun row => size row=32) (map (fun i => pad (f i)) (range 0 n)).
  + rewrite all_map; apply/allP => i hi; rewrite /pad; smt(mem_range size_cat size_nseq).
  have hg : all (fun row => size row=32) (map (fun i => pad (g i)) (range 0 n)).
  + rewrite all_map; apply/allP => i hi; rewrite /pad; smt(mem_range size_cat size_nseq).
  have hfc : chunk 32 (flatten (map (fun i => pad (f i)) (range 0 n))) =
    map (fun i => pad (f i)) (range 0 n) by apply flattenK; smt(allP).
  have hgc : chunk 32 (flatten (map (fun i => pad (g i)) (range 0 n))) =
    map (fun i => pad (g i)) (range 0 n) by apply flattenK; smt(allP).
  have hr : map (fun i => pad (f i)) (range 0 n) =
    map (fun i => pad (g i)) (range 0 n) by smt().
  move=> i hi.
  have hir : 0<=i<size (range 0 n) by smt(size_range).
  have hnf := nth_map 0 [] (fun j => pad (f j)) i (range 0 n) hir.
  have hng := nth_map 0 [] (fun j => pad (g j)) i (range 0 n) hir.
  have hn : nth 0 (range 0 n) i=i by smt(nth_range).
  have hp : pad (f i)=pad (g i) by smt().
  move: hp; rewrite /pad; smt(catIs).
qed.

lemma wots_endpoint_width h s seed layer tree kp i :
  size (wots_endpoint h s seed layer tree kp i)=16.
proof. apply linear_value_width; rewrite /wots_start; smt(node_width). qed.

lemma matching_wots_endpoints h s seed layer tree kp d sigma root leaf :
  !public_node_collision h => wots_root h s seed layer tree kp root =>
  all (fun row => size row=16) sigma =>
  h.[recovery_leaf_input h seed layer tree kp d sigma]=Some leaf => node leaf=root =>
  forall i, 0<=i<43 =>
    recovery_endpoint h seed layer tree kp d sigma i = wots_endpoint h s seed layer tree kp i.
proof.
  move=> hc [hp [rd [hr hv]]] hw hl he.
  have hi : recovery_leaf_input h seed layer tree kp d sigma = wots_leaf_input h s seed layer tree kp.
  + apply (recorded_node_equal_input h) => //; smt(domE).
  have hf : flatten (recovery_elements h seed layer tree kp d sigma 43) =
    flatten (wots_elements h s seed layer tree kp 43).
  + move: hi; rewrite /recovery_leaf_input /wots_leaf_input -!catA; smt(catsI).
  apply (padded_rows_injective (recovery_endpoint h seed layer tree kp d sigma)
    (wots_endpoint h s seed layer tree kp) 43) => //.
  smt(recovery_endpoint_width wots_endpoint_width).
qed.
