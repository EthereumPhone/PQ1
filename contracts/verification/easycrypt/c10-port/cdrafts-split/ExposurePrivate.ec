(* Retained output coordinates identify actual private values outside collisions. *)
require import AllCore List FMap.
require import C10RawOracle C10HashDomains RawKeygen RawForest RawSigner RawSignature.
require import ExposureLog ExposureSupport ExposureReferences ExposureWidths.
require import ForestRootWitness ForestRecordExtraction MemoNodeCollision ForsPrivateLeaves.

lemma logged_digest_private h s seed root entries message (signature : raw_signature) d :
  exposures_supported h s seed root entries => exposures_width entries =>
  List.mem entries (message,signature) =>
  h.[hmsg_input seed root (pad signature.`1) message]=Some d =>
  !public_node_collision h =>
  forest_private_openings h s seed (hypertree_index d) d signature.`2.
proof.
  move=> hs hw hm hd hn.
  have hwidth : signature_width signature by smt().
  have [ha [forest lower upper top [hr [hf htail]]]] :=
    logged_digest_references h s seed root entries message signature d hs hm hd.
  apply (recorded_forest_extracts h s seed (hypertree_index d) d signature.`2 signature.`3 forest)
    => //; move: hwidth; rewrite /signature_width; smt().
qed.

lemma logged_fors_private_value h s seed root entries ht tree index value :
  exposures_supported h s seed root entries => exposures_width entries =>
  !public_node_collision h => logged_fors_value h seed root entries ht tree index value =>
  exists sd, s.[fors_private_key ht tree index]=Some sd /\ value=node sd.
proof.
  move=> hs hw hn [message signature d [hm [hd [hh [htr [hi hv]]]]]].
  have [hp hl] := logged_digest_private h s seed root entries message signature d hs hw hm hd hn.
  have hwidth : signature_width signature by smt().
  have he : nth [] signature.`2 tree=nth (nseq 16 0) signature.`2 tree
    by move: hwidth; rewrite /signature_width /rows_width; smt(nth_change_dfl).
  have [sd [hsecret hval]] := hp tree htr.
  exists sd; smt().
qed.

lemma logged_special_private_root h s seed root entries ht value :
  exposures_supported h s seed root entries => exposures_width entries =>
  !public_node_collision h => logged_special_root h seed root entries ht value =>
  ForsRootWitness.fors_root_witness h s seed ht 12 value.
proof.
  move=> hs hw hn [message signature d [hm [hd [hh hv]]]].
  have [hp hl] := logged_digest_private h s seed root entries message signature d hs hw hm hd hn.
  have hwidth : signature_width signature by smt().
  have he : nth [] signature.`2 12=nth (nseq 16 0) signature.`2 12
    by move: hwidth; rewrite /signature_width /rows_width; smt(nth_change_dfl).
  smt().
qed.
