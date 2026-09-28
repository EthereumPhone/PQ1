(* Coordinate coverage may combine different previous responses for different trees. *)
require import AllCore List FMap.
require import C10RawOracle C10HashDomains RawKeygen RawForest RawSigner RawSignature.
require import ExposureLog ExposureSupport ExposureReferences ExposureWidths ExposurePrivate.
require import ForestRootWitness ForsRootWitness ForsRootDeterminism ForsPrivateLeaves MemoNodeCollision.

op logged_digest h seed root (entries : signing_exposure list) (d : digest) =
  exists message signature, List.mem entries (message,signature) /\
    h.[hmsg_input seed root (pad signature.`1) message]=Some d.
op returned_coordinate h seed root entries ht tree index =
  0<=tree<12 /\ exists d, logged_digest h seed root entries d /\
    hypertree_index d=ht /\ forest_index d tree=index.
op returned_coverage h seed root entries d =
  forall tree, 0<=tree<12 =>
    returned_coordinate h seed root entries (hypertree_index d) tree (forest_index d tree).

lemma returned_coordinate_value h seed root entries ht tree index :
  returned_coordinate h seed root entries ht tree index <=>
  exists value, logged_fors_value h seed root entries ht tree index value.
proof. rewrite /returned_coordinate /logged_digest /logged_fors_value; smt(). qed.

lemma returned_coverage_empty h seed root d : !returned_coverage h seed root [] d.
proof. rewrite /returned_coverage /returned_coordinate /logged_digest /=; smt(). qed.

lemma returned_coverage_repeat h seed root entries d :
  returned_coverage h seed root (entries++entries) d = returned_coverage h seed root entries d.
proof. rewrite /returned_coverage /returned_coordinate /logged_digest; smt(mem_cat). qed.

lemma returned_coordinate_cat h seed root entries1 entries2 ht tree index :
  returned_coordinate h seed root (entries1++entries2) ht tree index =
  (returned_coordinate h seed root entries1 ht tree index \/ returned_coordinate h seed root entries2 ht tree index).
proof. rewrite /returned_coordinate /logged_digest; smt(mem_cat). qed.

lemma logged_digest_covers_itself h seed root entries d :
  logged_digest h seed root entries d => returned_coverage h seed root entries d.
proof. rewrite /returned_coverage /returned_coordinate; smt(). qed.

lemma private_covered_value h s seed root entries d secrets tree :
  exposures_supported h s seed root entries => exposures_width entries =>
  !public_node_collision h => forest_private_openings h s seed (hypertree_index d) d secrets =>
  returned_coordinate h seed root entries (hypertree_index d) tree (forest_index d tree) =>
  logged_fors_value h seed root entries (hypertree_index d) tree (forest_index d tree)
    (nth (nseq 16 0) secrets tree).
proof.
  move=> hs hw hn [hp hl] hc.
  have [value hv] : exists value, logged_fors_value h seed root entries (hypertree_index d) tree (forest_index d tree) value
    by smt(returned_coordinate_value).
  have [sd [hd he]] := logged_fors_private_value h s seed root entries (hypertree_index d)
    tree (forest_index d tree) value hs hw hn hv.
  have htr : 0<=tree<12 by move: hc; rewrite /returned_coordinate; smt().
  have [sd' [hd' he']] := hp tree htr.
  have heq : value=nth (nseq 16 0) secrets tree by smt().
  by rewrite -heq.
qed.

lemma coverage_returns_special h s seed root entries d secrets :
  exposures_supported h s seed root entries => exposures_width entries =>
  !public_node_collision h => forest_private_openings h s seed (hypertree_index d) d secrets =>
  returned_coverage h seed root entries d =>
  logged_special_root h seed root entries (hypertree_index d) (nth (nseq 16 0) secrets 12).
proof.
  move=> hs hw hn [hp hl] hc.
  have [htr [old [ho [hh hi]]]] := hc 0 _; first smt().
  have [message signature [hm hd]] := ho.
  have hv : logged_special_root h seed root entries (hypertree_index d) (nth [] signature.`2 12)
    by exists message signature old; smt().
  have hr := logged_special_private_root h s seed root entries (hypertree_index d)
    (nth [] signature.`2 12) hs hw hn hv.
  have he := fors_root_witness_unique h s seed (hypertree_index d) 12
    (nth [] signature.`2 12) (nth (nseq 16 0) secrets 12) hr hl.
  smt().
qed.

op unreturned_private_opening h s seed root entries d (secrets : raw_input list) =
  exists tree sd, 0<=tree<12 /\
    !returned_coordinate h seed root entries (hypertree_index d) tree (forest_index d tree) /\
    s.[fors_private_key (hypertree_index d) tree (forest_index d tree)]=Some sd /\
    nth (nseq 16 0) secrets tree=node sd.
op returned_private_values h seed root entries d (secrets : raw_input list) =
  (forall tree, 0<=tree<12 => logged_fors_value h seed root entries (hypertree_index d)
    tree (forest_index d tree) (nth (nseq 16 0) secrets tree)) /\
  logged_special_root h seed root entries (hypertree_index d) (nth (nseq 16 0) secrets 12).

lemma unreturned_excludes_logged_values h s seed root entries d secrets :
  unreturned_private_opening h s seed root entries d secrets =>
  exists tree sd, 0<=tree<12 /\
    (forall value, !logged_fors_value h seed root entries (hypertree_index d) tree (forest_index d tree) value) /\
    s.[fors_private_key (hypertree_index d) tree (forest_index d tree)]=Some sd /\
    nth (nseq 16 0) secrets tree=node sd.
proof. rewrite /unreturned_private_opening; smt(returned_coordinate_value). qed.

lemma private_opening_coverage_partition h s seed root entries d secrets :
  exposures_supported h s seed root entries => exposures_width entries =>
  !public_node_collision h => forest_private_openings h s seed (hypertree_index d) d secrets =>
  (returned_coverage h seed root entries d /\ returned_private_values h seed root entries d secrets) \/
    unreturned_private_opening h s seed root entries d secrets.
proof.
  move=> hs hw hn hp; case (returned_coverage h seed root entries d) => hc.
  + left; split; first trivial.
    rewrite /returned_private_values; split.
    - move=> tree ht; apply (private_covered_value h s seed root entries d secrets tree) => //; exact (hc tree ht).
    exact (coverage_returns_special h s seed root entries d secrets hs hw hn hp hc).
  right; rewrite /unreturned_private_opening.
  have [tree [ht hu]] : exists tree, 0<=tree<12 /\
    !returned_coordinate h seed root entries (hypertree_index d) tree (forest_index d tree)
    by move: hc; rewrite /returned_coverage; smt().
  have [hp0 hp1] := hp.
  have [sd [hd hv]] := hp0 tree ht.
  exists tree sd; smt().
qed.
