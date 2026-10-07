(* An unreturned coordinate is not hidden merely by being unreturned.
   Here only equality to other retained private/public nodes is excluded. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawForest RawSigner RawSignature C10RawGrind ForsPrivateLeaves.
require import JointNodeCollision ExposureCoverage ExposurePartition ExposureComponents.
require import ForestOpeningCases MerkleRootWitness ExposureLog ExposureAccounting C10HashDomains.

op unaliased_private_opening h s seed root entries d (secrets : raw_input list) =
  exists tree sd, 0<=tree<12 /\
    !returned_coordinate h seed root entries (hypertree_index d) tree (forest_index d tree) /\
    s.[fors_private_key (hypertree_index d) tree (forest_index d tree)]=Some sd /\
    nth (nseq 16 0) secrets tree=node sd /\
    !node_known_elsewhere h s (fors_private_key (hypertree_index d) tree (forest_index d tree)) (node sd).

op aliased_private_opening h s seed root entries d (secrets : raw_input list) =
  exists tree sd, 0<=tree<12 /\
    !returned_coordinate h seed root entries (hypertree_index d) tree (forest_index d tree) /\
    s.[fors_private_key (hypertree_index d) tree (forest_index d tree)]=Some sd /\
    nth (nseq 16 0) secrets tree=node sd /\
    node_known_elsewhere h s (fors_private_key (hypertree_index d) tree (forest_index d tree)) (node sd).

lemma aliased_opening_implies_private_alias h s seed root entries d secrets :
  aliased_private_opening h s seed root entries d secrets => private_node_alias h s.
proof. rewrite /aliased_private_opening; smt(private_value_known_elsewhere). qed.

lemma unreturned_value_partition h s seed root entries d secrets :
  unreturned_private_opening h s seed root entries d secrets =>
  aliased_private_opening h s seed root entries d secrets \/
    unaliased_private_opening h s seed root entries d secrets.
proof.
  rewrite /unreturned_private_opening /aliased_private_opening /unaliased_private_opening; smt().
qed.

lemma unreturned_without_alias h s seed root entries d secrets :
  !private_node_alias h s => unreturned_private_opening h s seed root entries d secrets =>
  unaliased_private_opening h s seed root entries d secrets.
proof. smt(unreturned_value_partition aliased_opening_implies_private_alias). qed.

op unaliased_forgery_cases h s seed root entries d (sig : raw_signature) =
  new_top_component h s seed root entries d sig \/
  new_bottom_component h s seed root entries d sig \/
  (linked_private_openings h s seed d sig /\
    unaliased_private_opening h s seed root entries d sig.`2) \/
  (linked_private_openings h s seed d sig /\
    returned_coverage h seed root entries d /\ returned_private_values h seed root entries d sig.`2).

lemma exposure_cases_without_alias h s seed root entries d sig :
  !private_node_alias h s => exposure_forgery_cases h s seed root entries d sig =>
  unaliased_forgery_cases h s seed root entries d sig.
proof.
  rewrite /exposure_forgery_cases /unaliased_forgery_cases;
    smt(unreturned_without_alias).
qed.

op new_message_unaliased_partition h s seed root entries =
  merkle_root_witness h s seed 1 0 root /\
  exists message sig d, size message=32 /\ signature_width sig /\
    !List.mem (exposure_messages entries) message /\ accept_digest d /\
    h.[hmsg_input seed (pad root) (pad sig.`1) message]=Some d /\
    unaliased_forgery_cases h s seed (pad root) entries d sig.

lemma message_partition_without_alias h s seed root entries :
  !private_node_alias h s => new_message_exposure_partition h s seed root entries =>
  new_message_unaliased_partition h s seed root entries.
proof.
  rewrite /new_message_exposure_partition /new_message_unaliased_partition;
    smt(exposure_cases_without_alias).
qed.
