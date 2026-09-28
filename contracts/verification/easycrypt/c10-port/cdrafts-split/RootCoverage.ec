(* A retained complete root supplies a reference at any later chosen index. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen RawFors RawPathReplay RawSignature LayerPath.
require import NodeCatalog NodeCatalogDomain NodeGridIndex NodeGridPath CatalogPath CatalogWidths.
require import AuthCaptureIndex AuthCaptureSchedule DyadicStack StackPowers.
require import WotsReferenceRoot WotsCatalog MerkleRootWitness.

lemma wots_catalog_width h s seed layer tree c :
  catalog_sound h (merkle_pair seed layer tree) c =>
  wots_catalog h s seed layer tree c => catalog_width c.
proof.
  move=> hs hw; rewrite /catalog_width; move=> [level index] value hv.
  have hm : (level,index) \in c by smt(domE).
  have [hl [hi hp]] := hs level index hm.
  case (level=0) => hz.
  + have hx := hw index value _; first smt().
    move: hx; rewrite /wots_root; smt(node_width).
  have hx : catalog_link h (merkle_pair seed layer tree) c level index by smt().
  move: hx; rewrite /catalog_link; smt(node_width).
qed.

lemma catalog_sibling_due total target height :
  0<=height<total => 0<=target<2^total =>
  node_due (2^total) height (sibling_index (target %/ (2^height))).
proof.
  move=> hh ht.
  have hp := pow2_pos height _; first smt().
  have he : 2^(height+1)=2*2^height by rewrite exprS; smt().
  have hs := sibling_parent_cases (target %/ (2^height)).
  have hd := dyadic_index_step target height _; first smt().
  have hr := dyadic_index_range target (height+1) total _ ht; first smt().
  have hc := pair_capture_final total target height hh ht.
  move: hc; rewrite /target_pair_edge /node_right_edge /node_due; smt().
qed.

lemma complete_grid_auth_width c total target :
  0<=total => 0<=target<2^total => catalog_exact c (2^total) =>
  catalog_width c => rows_width total (grid_auth (catalog_grid c) target total).
proof.
  move=> hh ht hc hw.
  rewrite /rows_width /grid_auth size_mkseq; split; first smt().
  apply (all_nthP (fun x : raw_input => size x=16) _ []).
  move=> level hl; move: hl; rewrite size_mkseq; move=> hl.
  rewrite nth_mkseq 1:/# /catalog_grid.
  have hd := catalog_sibling_due total target level _ ht; first smt().
  have hm : (level,sibling_index (target %/ (2^level))) \in c by apply hc.
  have he := get_some c (level,sibling_index (target %/ (2^level))) hm.
  move: hw; rewrite /catalog_width; smt().
qed.

lemma root_reference_at h s seed layer tree root target :
  merkle_root_witness h s seed layer tree root => 0<=target<512 =>
  exists leaf auth, rows_width 9 auth /\
    wots_root h s seed layer tree target leaf /\
    layer_path h seed layer tree target leaf auth root.
proof.
  move=> [c [hc [hs [hw hr]]]] ht.
  have ht' : 0<=target<2^9 by smt(stack_pow2_9).
  have hc' : catalog_exact c (2^9) by smt(stack_pow2_9).
  have hwidth := wots_catalog_width h s seed layer tree c hs hw.
  have ha := complete_grid_auth_width c 9 target _ ht' hc' hwidth; first smt().
  have hp := catalog_recorded_path h (merkle_pair seed layer tree) c 9 target _ ht' hc' hs; first smt().
  have hm : (0,target) \in c by apply hc; rewrite /node_due /node_right_edge expr0; smt().
  have hl := wots_catalog_target h s seed layer tree c target hm hw.
  exists (catalog_grid c 0 target) (grid_auth (catalog_grid c) target 9).
  rewrite /layer_path; smt().
qed.
