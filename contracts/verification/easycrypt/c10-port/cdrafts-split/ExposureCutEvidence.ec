(* Actual returned-signature openings contradict an unreturned selected cut. *)
require import AllCore List FMap IntDiv RadixEncoding.
require import C10RawOracle RawKeygen RawForest RawSigner.
require import PersistentGrind ExposureLog ExposureSupport ExposureReferences.
require import ForestRootWitness ForestRootUnique MerkleRootWitness LayerSignOpening.
require import ObservedCutEvidence ObservedSignerOpening ObservedWotsOpening WotsCutDisclosure WotsUnreturnedCut.

op exposure_cut_opened h s seed root (entries : signing_exposure list) layer tree kp index cut =
  exists message signature, mem entries (message,signature) /\
    returned_cut_opened h s seed root message signature layer tree kp index cut.
lemma exposure_cut_opened_extends h h' s s' seed root entries layer tree kp index cut :
  extends h h' => extends s s' => exposure_cut_opened h s seed root entries layer tree kp index cut =>
  exposure_cut_opened h' s' seed root entries layer tree kp index cut.
proof. rewrite /exposure_cut_opened; smt(returned_cut_opened_extends). qed.
lemma exposure_cut_opened_rcons h s seed root entries (entry : signing_exposure) layer tree kp index cut :
  exposure_cut_opened h s seed root (rcons entries entry) layer tree kp index cut =
  (exposure_cut_opened h s seed root entries layer tree kp index cut \/
    returned_cut_opened h s seed root entry.`1 entry.`2 layer tree kp index cut).
proof. rewrite /exposure_cut_opened; smt(mem_rcons). qed.

lemma logged_cut_disclosure h s seed root entries layer tree kp index cut :
  exposures_supported h s seed root entries =>
  exposure_cut_opened h s seed root entries layer tree kp index cut =>
  (layer=0 /\ exists d, bottom_disclosure h s seed root entries (512*tree+kp) d /\ digit 3 d index<=cut) \/
  (layer=1 /\ exists d, top_disclosure h s seed root entries kp d /\ digit 3 d index<=cut).
proof.
  move=> hs [message signature [hm [accepted [ha ho]]]].
  have [_ [forest lower upper top [hf [hb [hb' [hu ht]]]]]] :=
    logged_digest_references h s seed root entries message signature accepted hs hm ha.
  move: ho; rewrite /signed_cut_opened; move=> [hbcut|htcut].
  + have [hl [htr [hkp [forest' [hf' [d [hc hd]]]]]]] := hbcut.
    have he := forest_root_unique h s seed (hypertree_index accepted) forest forest' hf hf'.
    have hi : 512*tree+kp=hypertree_index accepted by smt(divz_eq).
    left; split; first exact hl.
    exists d; split; last exact hd.
    exists message signature accepted forest lower; smt().
  have [hl [htr [hkp [upper' [hu' [d [hc hd]]]]]]] := htcut.
  have he := merkle_root_witness_unique h s seed 0 (hypertree_index accepted %/512) upper upper' hu hu'.
  right; split; first exact hl.
  exists d; split; last exact hd.
  exists message signature accepted upper top; smt().
qed.
lemma exposure_cut_conflicts_unreturned h s seed root entries layer tree kp index cut :
  exposures_supported h s seed root entries =>
  (if layer=0 then bottom_cut_unreturned h s seed root entries (512*tree+kp) index cut
   else top_cut_unreturned h s seed root entries kp index cut) =>
  !exposure_cut_opened h s seed root entries layer tree kp index cut.
proof.
  move=> hs hu; case (exposure_cut_opened h s seed root entries layer tree kp index cut); last smt().
  move=> ho; have hd:=logged_cut_disclosure h s seed root entries layer tree kp index cut hs ho.
  move: hu; rewrite /bottom_cut_unreturned /top_cut_unreturned; smt().
qed.
