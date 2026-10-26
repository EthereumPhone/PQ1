(* Equal-address collision exclusion identifies all supplied forest secrets. *)
require import AllCore List FMap BitEncoding.
require import C10RawOracle RawKeygen RawSignature RawForest ForestCoordinates RawForsPathReplay.
require import PathReplay ForsOpening ForsLeafInputs ForestOpenings ForestWitness ForestOpening.
require import ForsRootWitness ForestRootWitness ForsRecordExtraction MemoNodeCollision LinearCollision.
import BitChunking.

require import ForestRecordExtraction NodeQueryDomain DomainNodeCollision DomainPathInputs DomainForsExtraction HmsgShapes ClientGuessCandidates.

require import DomainForestExtraction AddressedNodeCollision AddressedForsExtraction.

lemma addressed_forest_compression_prefix seed ht roots refs :
  size seed=32 =>
  same_node_address (forest_compress_input seed ht roots)
    (forest_compress_input seed ht refs).
proof.
  move=> hs; rewrite /same_node_address /forest_compress_input.
  have hw := raw_address_width 0 ht 4 0 0 0 0.
  by rewrite (node_prefix seed _ _ hs hw) (node_prefix seed _ _ hs hw).
qed.

lemma addressed_forest_special_prefix seed ht value reference :
  size seed=32 =>
  same_node_address (forest_special_input seed ht value)
    (forest_special_input seed ht reference).
proof.
  rewrite /forest_special_input.
  exact (addressed_fors_leaf_same_address seed ht 12 0 value reference).
qed.

lemma addressed_recorded_forest_extracts h s seed ht digest secrets auths root :
  size seed=32 => rows_width 13 secrets => size auths=12 => all (rows_width 11) auths =>
  forest_root_witness h s seed ht root => forest_opening h seed ht digest secrets auths root =>
  !addressed_node_collision h => forest_private_openings h s seed ht digest secrets.
proof.
  move=> hseed hse hau hawa [refs lastroot special final [hrw [hrefs [hlast [hspecial [hlastrow [hfinal hr]]]]]]]
    [roots d [hw [hd hv]]] hn.
  have hrootsw := forest_witness_roots_width h seed ht digest secrets auths roots hw.
  have he : forest_compress_input seed ht roots=forest_compress_input seed ht refs.
  + have haddr := addressed_forest_compression_prefix seed ht roots refs hseed.
    apply (addressed_recorded_equal_input h) => //;
      smt(domE domain_forest_compress domain_forest_special rows_nth_width fors_root_witness_width).
  have hroots : roots=refs by apply (forest_compress_injective seed ht roots refs hrootsw hrw he).
  split.
  + move=> t hi.
    have hf : fors_opening h seed ht t (forest_index digest t)
      (nth (nseq 16 0) secrets t) (nth [] auths t) (nth (nseq 16 0) refs t)
      by move: hw; rewrite /forest_witness /forest_openings; smt(mem_range).
    apply (addressed_recorded_fors_extracts h s seed ht t (forest_index digest t)
      (nth (nseq 16 0) secrets t) (nth [] auths t) (nth (nseq 16 0) refs t)) => //.
    - move: hse; rewrite /rows_width; smt(allP mem_nth).
    - smt(allP mem_nth).
    - smt(forest_index_range).
    exact (hrefs t hi).
  have [lastd [he' hv']] : exists lastd,
    h.[forest_special_input seed ht (nth (nseq 16 0) secrets 12)]=Some lastd /\
    nth (nseq 16 0) roots 12=node lastd by move: hw; rewrite /forest_witness; smt().
  have hi : forest_special_input seed ht (nth (nseq 16 0) secrets 12)=forest_special_input seed ht lastroot.
  + have haddr := addressed_forest_special_prefix seed ht
      (nth (nseq 16 0) secrets 12) lastroot hseed.
    apply (addressed_recorded_equal_input h) => //;
      smt(domE domain_forest_compress domain_forest_special rows_nth_width fors_root_witness_width).
  have hlastvalue : nth (nseq 16 0) secrets 12=lastroot
    by move: hi; rewrite /forest_special_input; smt(fors_leaf_input_injective).
  smt().
qed.
