(* Matching recorded forest compression identifies every actual supplied secret. *)
require import AllCore List FMap BitEncoding.
require import C10RawOracle RawKeygen RawSignature RawForest ForestCoordinates RawForsPathReplay.
require import PathReplay ForsOpening ForsLeafInputs ForestOpenings ForestWitness ForestOpening.
require import ForsRootWitness ForestRootWitness ForsRecordExtraction MemoNodeCollision LinearCollision.
import BitChunking.

require import ForestRecordExtraction NodeQueryDomain DomainNodeCollision DomainPathInputs DomainForsExtraction HmsgShapes ClientGuessCandidates.

lemma domain_forest_compress seed ht roots :
  size seed=32 => rows_width 13 roots => node_query (forest_compress_input seed ht roots).
proof.
  move=> hs hw; rewrite /forest_compress_input; apply (node_query_compress _ _ _ 13) => //.
  exact (raw_address_width _ _ _ _ _ _ _).
qed.
lemma domain_forest_special seed ht secret :
  size seed=32 => size secret=16 => node_query (forest_special_input seed ht secret).
proof. rewrite /forest_special_input; exact (domain_fors_leaf _ _ _ _ _). qed.

lemma domain_recorded_forest_extracts h s seed ht digest secrets auths root :
  size seed=32 => rows_width 13 secrets => size auths=12 => all (rows_width 11) auths =>
  forest_root_witness h s seed ht root => forest_opening h seed ht digest secrets auths root =>
  !domain_node_collision h => forest_private_openings h s seed ht digest secrets.
proof.
  move=> hseed hse hau hawa [refs lastroot special final [hrw [hrefs [hlast [hspecial [hlastrow [hfinal hr]]]]]]]
    [roots d [hw [hd hv]]] hn.
  have hrootsw := forest_witness_roots_width h seed ht digest secrets auths roots hw.
  have he : forest_compress_input seed ht roots=forest_compress_input seed ht refs.
  + apply (domain_recorded_equal_input h) => //; smt(domE domain_forest_compress domain_forest_special rows_nth_width fors_root_witness_width).
  have hroots : roots=refs by apply (forest_compress_injective seed ht roots refs hrootsw hrw he).
  split.
  + move=> t hi.
    have hf : fors_opening h seed ht t (forest_index digest t)
      (nth (nseq 16 0) secrets t) (nth [] auths t) (nth (nseq 16 0) refs t)
      by move: hw; rewrite /forest_witness /forest_openings; smt(mem_range).
    apply (domain_recorded_fors_extracts h s seed ht t (forest_index digest t)
      (nth (nseq 16 0) secrets t) (nth [] auths t) (nth (nseq 16 0) refs t)) => //.
    - move: hse; rewrite /rows_width; smt(allP mem_nth).
    - smt(allP mem_nth).
    - smt(forest_index_range).
    exact (hrefs t hi).
  have [lastd [he' hv']] : exists lastd,
    h.[forest_special_input seed ht (nth (nseq 16 0) secrets 12)]=Some lastd /\
    nth (nseq 16 0) roots 12=node lastd by move: hw; rewrite /forest_witness; smt().
  have hi : forest_special_input seed ht (nth (nseq 16 0) secrets 12)=forest_special_input seed ht lastroot.
  + apply (domain_recorded_equal_input h) => //; smt(domE domain_forest_compress domain_forest_special rows_nth_width fors_root_witness_width).
  have hlastvalue : nth (nseq 16 0) secrets 12=lastroot
    by move: hi; rewrite /forest_special_input; smt(fors_leaf_input_injective).
  smt().
qed.
