(* Adaptive repeat requests cannot lower the disclosed position of an honest WOTS key. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle C10HashDomains RawKeygen RawForest RawSigner.
require import ExposureLog ExposureSupport MinimumExposureSupport MinimumExposureReferences.
require import ForestRootUnique MerkleRootWitness WotsCanonicalReturn.

lemma repeated_bottom_signature h s seed root entries message signature d message' signature' d' :
  exposures_supported h s seed root entries => minimum_entries h s seed root entries =>
  List.mem entries (message,signature) => List.mem entries (message',signature') =>
  h.[hmsg_input seed root (pad signature.`1) message]=Some d =>
  h.[hmsg_input seed root (pad signature'.`1) message']=Some d' =>
  hypertree_index d=hypertree_index d' =>
  (nth ([],0,[]) signature.`4 0).`2=(nth ([],0,[]) signature'.`4 0).`2 /\
  (nth ([],0,[]) signature.`4 0).`1=(nth ([],0,[]) signature'.`4 0).`1.
proof.
  move=> hs hn hm hm' hd hd' hi.
  have [forest lower upper top [hf [hb [hc rest]]]] :=
    logged_minimal_component_openings h s seed root entries message signature d hs hn hm hd.
  have [forest' lower' upper' top' [hf' [hb' [hc' rest']]]] :=
    logged_minimal_component_openings h s seed root entries message' signature' d' hs hn hm' hd'.
  have hf'' : ForestRootWitness.forest_root_witness h s seed (hypertree_index d) forest' by smt().
  have he := forest_root_unique h s seed (hypertree_index d) forest forest' hf hf''.
  apply (canonical_layer_return h s seed 0 (hypertree_index d %/512) (hypertree_index d %%512)
    forest (nth ([],0,[]) signature.`4 0) (nth ([],0,[]) signature'.`4 0) lower lower'); smt().
qed.

lemma repeated_top_signature h s seed root entries message signature d message' signature' d' :
  exposures_supported h s seed root entries => minimum_entries h s seed root entries =>
  List.mem entries (message,signature) => List.mem entries (message',signature') =>
  h.[hmsg_input seed root (pad signature.`1) message]=Some d =>
  h.[hmsg_input seed root (pad signature'.`1) message']=Some d' =>
  hypertree_index d %/512=hypertree_index d' %/512 =>
  (nth ([],0,[]) signature.`4 1).`2=(nth ([],0,[]) signature'.`4 1).`2 /\
  (nth ([],0,[]) signature.`4 1).`1=(nth ([],0,[]) signature'.`4 1).`1.
proof.
  move=> hs hn hm hm' hd hd' hi.
  have [forest lower upper top [hf [hb [hc [hr [ht hct]]]]]] :=
    logged_minimal_component_openings h s seed root entries message signature d hs hn hm hd.
  have [forest' lower' upper' top' [hf' [hb' [hc' [hr' [ht' hct']]]]]] :=
    logged_minimal_component_openings h s seed root entries message' signature' d' hs hn hm' hd'.
  have hr'' : merkle_root_witness h s seed 0 (hypertree_index d %/512) upper' by smt().
  have he := merkle_root_witness_unique h s seed 0 (hypertree_index d %/512) upper upper' hr hr''.
  apply (canonical_layer_return h s seed 1 0 (hypertree_index d %/512)
    upper (nth ([],0,[]) signature.`4 1) (nth ([],0,[]) signature'.`4 1) top top'); smt().
qed.
