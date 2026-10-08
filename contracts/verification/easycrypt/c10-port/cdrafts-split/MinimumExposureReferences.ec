(* Align minimal-counter references with the exact messages of retained openings. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains RawKeygen RawForest RawSigner.
require import ExposureLog ExposureSupport ExposureReferences MinimumExposureSupport.
require import HonestMinimumCounts SignerMinimumCounts LayerMinimumCounts.
require import ForestRootWitness ForestRootUnique MerkleRootWitness LayerSignOpening.

lemma logged_minimum_digest h s seed root entries message signature d :
  minimum_entries h s seed root entries => List.mem entries (message,signature) =>
  h.[hmsg_input seed root (pad signature.`1) message]=Some d =>
  signed_minimum_counts h s seed (hypertree_index d) signature.`4.
proof.
  rewrite /minimum_entries /minimum_entry /returned_minimum_counts /=; smt().
qed.

lemma minimum_bottom_reference h s seed ht layers forest :
  signed_minimum_counts h s seed ht layers => forest_root_witness h s seed ht forest =>
  minimal_layer_count h seed 0 (ht %/512) (ht %%512) forest (nth ([],0,[]) layers 0).
proof.
  move=> [forest' [hf [hc ht']]] hf'.
  have he := forest_root_unique h s seed ht forest' forest hf hf'; smt().
qed.

lemma minimum_top_reference h s seed ht layers lower :
  signed_minimum_counts h s seed ht layers => merkle_root_witness h s seed 0 (ht %/512) lower =>
  minimal_layer_count h seed 1 0 (ht %/512) lower (nth ([],0,[]) layers 1).
proof.
  move=> [forest [hf [hc [lower' [hr hc_top]]]]] hr'.
  have he := merkle_root_witness_unique h s seed 0 (ht %/512) lower' lower hr hr'; smt().
qed.

lemma logged_minimal_component_openings h s seed root entries message signature d :
  exposures_supported h s seed root entries => minimum_entries h s seed root entries =>
  List.mem entries (message,signature) =>
  h.[hmsg_input seed root (pad signature.`1) message]=Some d =>
  exists forest lower upper top,
    forest_root_witness h s seed (hypertree_index d) forest /\
    layer_opening h s seed 0 (hypertree_index d %/512) (hypertree_index d %%512)
      forest (nth ([],0,[]) signature.`4 0) lower /\
    minimal_layer_count h seed 0 (hypertree_index d %/512) (hypertree_index d %%512)
      forest (nth ([],0,[]) signature.`4 0) /\
    merkle_root_witness h s seed 0 (hypertree_index d %/512) upper /\
    layer_opening h s seed 1 0 (hypertree_index d %/512)
      upper (nth ([],0,[]) signature.`4 1) top /\
    minimal_layer_count h seed 1 0 (hypertree_index d %/512)
      upper (nth ([],0,[]) signature.`4 1).
proof.
  move=> hs hn hm hd.
  have [ha [forest lower upper top [hf [ho [hb [hr ht]]]]]] :=
    logged_digest_references h s seed root entries message signature d hs hm hd.
  have hc := logged_minimum_digest h s seed root entries message signature d hn hm hd.
  have hb' := minimum_bottom_reference h s seed (hypertree_index d) signature.`4 forest hc hf.
  have ht' := minimum_top_reference h s seed (hypertree_index d) signature.`4 upper hc hr.
  exists forest lower upper top; smt().
qed.
