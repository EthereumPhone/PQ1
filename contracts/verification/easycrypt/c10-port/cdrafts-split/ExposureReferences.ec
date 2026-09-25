(* A logged output's accepted digest selects both complete retained references. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains KeygenPrefixes RawKeygen RawForest RawSigner ExposureLog ExposureSupport.
require import HonestForestMessages HonestSubtreeMessages SignerForestReference SignerSubtreeReference.
require import ForestRootWitness ForestOpening MerkleRootWitness LayerSignOpening.

lemma exposure_shared_digest h s seed root message signature :
  exposure_supported h s seed root (message,signature) =>
  exists d, accept_digest d /\ h.[hmsg_input seed root (pad signature.`1) message]=Some d /\
    signed_forest_reference h s seed d signature /\
    signed_subtree_reference h s seed (hypertree_index d) signature.`4.
proof.
  rewrite /exposure_supported /returned_forest_reference /returned_subtree_reference /=.
  move=> [[d [ha [he hf]]] [d' [ha' [he' ht]]]].
  exists d; smt().
qed.

lemma logged_digest_references h s seed root entries message signature d :
  exposures_supported h s seed root entries => List.mem entries (message,signature) =>
  h.[hmsg_input seed root (pad signature.`1) message]=Some d =>
  accept_digest d /\ exists forest lower upper top,
    forest_root_witness h s seed (hypertree_index d) forest /\
    forest_opening h seed (hypertree_index d) d signature.`2 signature.`3 forest /\
    layer_opening h s seed 0 (hypertree_index d %/512) (hypertree_index d %%512)
      forest (nth ([],0,[]) signature.`4 0) lower /\
    merkle_root_witness h s seed 0 (hypertree_index d %/512) upper /\
    layer_opening h s seed 1 0 (hypertree_index d %/512)
      upper (nth ([],0,[]) signature.`4 1) top.
proof.
  move=> hall hm he.
  have hs : exposure_supported h s seed root (message,signature) by smt().
  have [d' [ha [he' [hf ht]]]] := exposure_shared_digest h s seed root message signature hs.
  have hd : d'=d by smt().
  move: hf ht; rewrite hd /signed_forest_reference /signed_subtree_reference; smt().
qed.

op logged_fors_value h seed root (entries : signing_exposure list) ht tree index value =
  exists message signature d, List.mem entries (message,signature) /\
    h.[hmsg_input seed root (pad signature.`1) message]=Some d /\
    hypertree_index d=ht /\ 0<=tree<12 /\ forest_index d tree=index /\
    nth [] signature.`2 tree=value.
op logged_special_root h seed root (entries : signing_exposure list) ht value =
  exists message signature d, List.mem entries (message,signature) /\
    h.[hmsg_input seed root (pad signature.`1) message]=Some d /\
    hypertree_index d=ht /\ nth [] signature.`2 12=value.

lemma logged_fors_has_forest_reference h s seed root entries ht tree index value :
  exposures_supported h s seed root entries => logged_fors_value h seed root entries ht tree index value =>
  exists forest, forest_root_witness h s seed ht forest.
proof.
  move=> hs [message signature d [hm [hd [hh hrest]]]].
  have [ha [forest lower upper top [hf htail]]] :=
    logged_digest_references h s seed root entries message signature d hs hm hd.
  exists forest; smt().
qed.

lemma absent_forest_excludes_logged_fors h s seed root entries ht :
  exposures_supported h s seed root entries =>
  (forall forest, !forest_root_witness h s seed ht forest) =>
  forall tree index value, !logged_fors_value h seed root entries ht tree index value.
proof. smt(logged_fors_has_forest_reference). qed.

lemma logged_special_has_forest_reference h s seed root entries ht value :
  exposures_supported h s seed root entries => logged_special_root h seed root entries ht value =>
  exists forest, forest_root_witness h s seed ht forest.
proof.
  move=> hs [message signature d [hm [hd [hh hv]]]].
  have [ha [forest lower upper top [hf htail]]] :=
    logged_digest_references h s seed root entries message signature d hs hm hd.
  exists forest; smt().
qed.
