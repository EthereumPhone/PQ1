(* Coordinate coverage may combine different previous responses for different trees. *)
require import AllCore List FMap.
require import C10RawOracle C10HashDomains RawKeygen RawForest RawSigner RawSignature.
require import ExposureLog ExposureSupport ExposureReferences ExposureWidths ExposurePrivate.
require import ForestRootWitness ForsRootWitness ForsRootDeterminism ForsPrivateLeaves MemoNodeCollision.

require import ExposureCoverage DomainNodeCollision DomainExposurePrivate.

lemma domain_private_covered_value h s seed root entries d secrets tree :
  size seed=32 => exposures_supported h s seed root entries => exposures_width entries =>
  !domain_node_collision h => forest_private_openings h s seed (hypertree_index d) d secrets =>
  returned_coordinate h seed root entries (hypertree_index d) tree (forest_index d tree) =>
  logged_fors_value h seed root entries (hypertree_index d) tree (forest_index d tree)
    (nth (nseq 16 0) secrets tree).
proof.
  move=> hseed hs hw hn [hp hl] hc.
  have [value hv] : exists value, logged_fors_value h seed root entries (hypertree_index d) tree (forest_index d tree) value
    by smt(returned_coordinate_value).
  have [sd [hd he]] := domain_logged_fors_private_value h s seed root entries (hypertree_index d)
    tree (forest_index d tree) value hseed hs hw hn hv.
  have htr : 0<=tree<12 by move: hc; rewrite /returned_coordinate; smt().
  have [sd' [hd' he']] := hp tree htr.
  have heq : value=nth (nseq 16 0) secrets tree by smt().
  by rewrite -heq.
qed.

lemma domain_coverage_returns_special h s seed root entries d secrets :
  size seed=32 => exposures_supported h s seed root entries => exposures_width entries =>
  !domain_node_collision h => forest_private_openings h s seed (hypertree_index d) d secrets =>
  returned_coverage h seed root entries d =>
  logged_special_root h seed root entries (hypertree_index d) (nth (nseq 16 0) secrets 12).
proof.
  move=> hseed hs hw hn [hp hl] hc.
  have [htr [old [ho [hh hi]]]] := hc 0 _; first smt().
  have [message signature [hm hd]] := ho.
  have hv : logged_special_root h seed root entries (hypertree_index d) (nth [] signature.`2 12)
    by exists message signature old; smt().
  have hr := domain_logged_special_private_root h s seed root entries (hypertree_index d)
    (nth [] signature.`2 12) hseed hs hw hn hv.
  have he := fors_root_witness_unique h s seed (hypertree_index d) 12
    (nth [] signature.`2 12) (nth (nseq 16 0) secrets 12) hr hl.
  smt().
qed.

lemma domain_private_opening_coverage_partition h s seed root entries d secrets :
  size seed=32 => exposures_supported h s seed root entries => exposures_width entries =>
  !domain_node_collision h => forest_private_openings h s seed (hypertree_index d) d secrets =>
  (returned_coverage h seed root entries d /\ returned_private_values h seed root entries d secrets) \/
    unreturned_private_opening h s seed root entries d secrets.
proof.
  move=> hseed hs hw hn hp; case (returned_coverage h seed root entries d) => hc.
  + left; split; first trivial.
    rewrite /returned_private_values; split.
    - move=> tree ht; apply (domain_private_covered_value h s seed root entries d secrets tree) => //; exact (hc tree ht).
    exact (domain_coverage_returns_special h s seed root entries d secrets hseed hs hw hn hp hc).
  right; rewrite /unreturned_private_opening.
  have [tree [ht hu]] : exists tree, 0<=tree<12 /\
    !returned_coordinate h seed root entries (hypertree_index d) tree (forest_index d tree)
    by move: hc; rewrite /returned_coverage; smt().
  have [hp0 hp1] := hp.
  have [sd [hd hv]] := hp0 tree ht.
  exists tree sd; smt().
qed.
