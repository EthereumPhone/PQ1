(* Matching recorded forest compression identifies every actual supplied secret. *)
require import AllCore List FMap BitEncoding.
require import C10RawOracle RawKeygen RawSignature RawForest ForestCoordinates RawForsPathReplay.
require import PathReplay ForsOpening ForsLeafInputs ForestOpenings ForestWitness ForestOpening.
require import ForsRootWitness ForestRootWitness ForsRecordExtraction MemoNodeCollision LinearCollision.
import BitChunking.

lemma path_value_width h f auth current level index :
  size current=16 => size (path_value h f (current,level,index) auth).`1=16.
proof.
  elim: auth current level index => [current level index | sibling rest ih current level index].
  + by rewrite /path_value /=.
  move=> hw; rewrite /path_value /=; apply ih; smt(node_width).
qed.

lemma fors_opening_root_width h seed ht tree target secret auth root :
  fors_opening h seed ht tree target secret auth root => size root=16.
proof.
  move=> [ha [d [hd [hp hv]]]].
  have hw := path_value_width h (fors_pair seed ht tree) auth (node d) 0 target (node_width d).
  smt().
qed.

lemma forest_witness_roots_width h seed ht digest secrets auths roots :
  forest_witness h seed ht digest secrets auths roots => rows_width 13 roots.
proof.
  move=> [[hse [hau [hro hp]]] [d [hd hv]]]; rewrite /rows_width hro; split; first smt().
  apply (all_nthP (fun x : raw_input => size x=16) _ (nseq 16 0)).
  move=> t hi; case (t=12) => he; first smt(node_width).
  have ho : fors_opening h seed ht t (forest_index digest t)
    (nth (nseq 16 0) secrets t) (nth [] auths t) (nth (nseq 16 0) roots t)
    by apply hp; smt(mem_range).
  exact (fors_opening_root_width h seed ht t (forest_index digest t)
    (nth (nseq 16 0) secrets t) (nth [] auths t) (nth (nseq 16 0) roots t) ho).
qed.

lemma forest_compress_injective seed ht roots roots' :
  rows_width 13 roots => rows_width 13 roots' =>
  forest_compress_input seed ht roots=forest_compress_input seed ht roots' => roots=roots'.
proof.
  move=> [hs hw] [hs' hw']; rewrite /forest_compress_input -!catA => he.
  have hf : flatten (map pad roots)=flatten (map pad roots') by smt(catsI).
  have ha : forall row, mem (map pad roots) row => size row=32.
  + move=> row /mapP [x [hx ->]]; rewrite /pad; smt(allP size_cat size_nseq).
  have hb : forall row, mem (map pad roots') row => size row=32.
  + move=> row /mapP [x [hx ->]]; rewrite /pad; smt(allP size_cat size_nseq).
  have hfa : chunk 32 (flatten (map pad roots))=map pad roots by apply flattenK; smt().
  have hfb : chunk 32 (flatten (map pad roots'))=map pad roots' by apply flattenK; smt().
  have hm : map pad roots=map pad roots' by smt().
  apply (eq_from_nth (nseq 16 0)); first smt().
  move=> i hi.
  have hi' : 0<=i<size roots' by smt().
  have hna := nth_map (nseq 16 0) [] pad i roots hi.
  have hnb := nth_map (nseq 16 0) [] pad i roots' hi'.
  have heq : pad (nth (nseq 16 0) roots i)=pad (nth (nseq 16 0) roots' i) by smt().
  move: heq; rewrite /pad; smt(catIs).
qed.

lemma recorded_forest_extracts h s seed ht digest secrets auths root :
  rows_width 13 secrets => size auths=12 => all (rows_width 11) auths =>
  forest_root_witness h s seed ht root => forest_opening h seed ht digest secrets auths root =>
  !public_node_collision h => forest_private_openings h s seed ht digest secrets.
proof.
  move=> hse hau hawa [refs lastroot special final [hrw [hrefs [hlast [hspecial [hlastrow [hfinal hr]]]]]]]
    [roots d [hw [hd hv]]] hn.
  have hrootsw := forest_witness_roots_width h seed ht digest secrets auths roots hw.
  have he : forest_compress_input seed ht roots=forest_compress_input seed ht refs.
  + apply (recorded_node_equal_input h) => //; smt(domE).
  have hroots : roots=refs by apply (forest_compress_injective seed ht roots refs hrootsw hrw he).
  split.
  + move=> t hi.
    have hf : fors_opening h seed ht t (forest_index digest t)
      (nth (nseq 16 0) secrets t) (nth [] auths t) (nth (nseq 16 0) refs t)
      by move: hw; rewrite /forest_witness /forest_openings; smt(mem_range).
    apply (recorded_fors_extracts h s seed ht t (forest_index digest t)
      (nth (nseq 16 0) secrets t) (nth [] auths t) (nth (nseq 16 0) refs t)) => //.
    - move: hse; rewrite /rows_width; smt(allP mem_nth).
    - smt(allP mem_nth).
    - smt(forest_index_range).
    exact (hrefs t hi).
  have [lastd [he' hv']] : exists lastd,
    h.[forest_special_input seed ht (nth (nseq 16 0) secrets 12)]=Some lastd /\
    nth (nseq 16 0) roots 12=node lastd by move: hw; rewrite /forest_witness; smt().
  have hi : forest_special_input seed ht (nth (nseq 16 0) secrets 12)=forest_special_input seed ht lastroot.
  + apply (recorded_node_equal_input h) => //; smt(domE).
  have hlastvalue : nth (nseq 16 0) secrets 12=lastroot
    by move: hi; rewrite /forest_special_input; smt(fors_leaf_input_injective).
  smt().
qed.
