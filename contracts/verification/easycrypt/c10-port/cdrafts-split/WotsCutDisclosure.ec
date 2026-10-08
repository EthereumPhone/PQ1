(* Canonical digest evidence is retained for every response that discloses a chain. *)
require import AllCore List FMap IntDiv RadixEncoding.
require import C10RawOracle C10HashDomains RawKeygen RawWots RawForest RawSigner RawCountRecorded.
require import ExposureLog ExposureSupport MinimumExposureSupport MinimumExposureReferences.
require import ForestRootWitness ForestRootUnique MerkleRootWitness WotsCanonicalReturn.
require import WotsFirstCount LayerMinimumCounts WotsSignatureValue WotsSignWitness WotsOpeningPersistent.

op bottom_disclosure h s seed root (entries : signing_exposure list) ht d =
  exists message signature accepted value lower,
    List.mem entries (message,signature) /\
    h.[hmsg_input seed root (pad signature.`1) message]=Some accepted /\ hypertree_index accepted=ht /\
    forest_root_witness h s seed ht value /\
    LayerSignOpening.layer_opening h s seed 0 (ht %/512) (ht %%512)
      value (nth ([],0,[]) signature.`4 0) lower /\
    first_wots_count h seed 0 (ht %/512) (ht %%512) value (nth ([],0,[]) signature.`4 0).`2 d.

op top_disclosure h s seed root (entries : signing_exposure list) tree d =
  exists message signature accepted value top,
    List.mem entries (message,signature) /\
    h.[hmsg_input seed root (pad signature.`1) message]=Some accepted /\ hypertree_index accepted %/512=tree /\
    merkle_root_witness h s seed 0 tree value /\
    LayerSignOpening.layer_opening h s seed 1 0 tree value (nth ([],0,[]) signature.`4 1) top /\
    first_wots_count h seed 1 0 tree value (nth ([],0,[]) signature.`4 1).`2 d.

lemma bottom_disclosure_unique h s seed root entries ht d d' :
  bottom_disclosure h s seed root entries ht d => bottom_disclosure h s seed root entries ht d' => d=d'.
proof.
  move=> [m sig a value lower [hm [ha [hi [hf [ho hc]]]]]]
    [m' sig' a' value' lower' [hm' [ha' [hi' [hf' [ho' hc']]]]]].
  have he := forest_root_unique h s seed ht value value' hf hf'.
  have hc'' : first_wots_count h seed 0 (ht %/512) (ht %%512) value (nth ([],0,[]) sig'.`4 0).`2 d' by smt().
  smt(first_wots_count_unique).
qed.

lemma top_disclosure_unique h s seed root entries tree d d' :
  top_disclosure h s seed root entries tree d => top_disclosure h s seed root entries tree d' => d=d'.
proof.
  move=> [m sig a value top [hm [ha [hi [hf [ho hc]]]]]]
    [m' sig' a' value' top' [hm' [ha' [hi' [hf' [ho' hc']]]]]].
  have he := merkle_root_witness_unique h s seed 0 tree value value' hf hf'.
  have hc'' : first_wots_count h seed 1 0 tree value (nth ([],0,[]) sig'.`4 1).`2 d' by smt().
  smt(first_wots_count_unique).
qed.

lemma logged_component_disclosures h s seed root entries message signature accepted :
  exposures_supported h s seed root entries => minimum_entries h s seed root entries =>
  List.mem entries (message,signature) =>
  h.[hmsg_input seed root (pad signature.`1) message]=Some accepted =>
  exists d d', bottom_disclosure h s seed root entries (hypertree_index accepted) d /\
    top_disclosure h s seed root entries (hypertree_index accepted %/512) d'.
proof.
  move=> hs hn hm hd.
  have [forest lower upper top [hf [hb [[d hc] [hr [ht [d' hc']]]]]]] :=
    logged_minimal_component_openings h s seed root entries message signature accepted hs hn hm hd.
  exists d d'; split.
  + exists message signature accepted forest lower; smt().
  exists message signature accepted upper top; smt().
qed.
