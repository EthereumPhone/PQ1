(* The event is attached to the exact pair passed to the initialized byte verifier. *)
require import AllCore List FMap.
require import C10RawOracle C10HashDomains RawKeygen RawForest RawSigner ForsPrivateLeaves.
require import ExposureLog ExposureCoverage ReturnedPrivateInputs TargetByteView TargetTableGames.
require import OriginalTargetEvent ForsCoordinateUniverse.

op actual_output_unreturned h s seed root entries (output : raw_input * raw_signature) =
  exists d, h.[hmsg_input seed root (pad output.`2.`1) output.`1]=Some d /\
    unreturned_private_opening h s seed root entries d output.`2.`2.

lemma ordinary_output_candidate_mem signature tree :
  0<=tree<12 => mem (ordinary_output_candidates signature) (nth (nseq 16 0) signature.`2 tree).
proof. move=> ht; rewrite /ordinary_output_candidates mapP; exists tree; rewrite mem_range; smt(). qed.

lemma actual_unreturned_candidates h s seed root entries output :
  actual_output_unreturned h s seed root entries output =>
  exists c, mem ordinary_fors_coordinates c /\
    unreturned_candidate_guess h s seed root entries (ordinary_output_candidates output.`2)
      (fors_private_key c.`1 c.`2 c.`3).
proof.
  rewrite /actual_output_unreturned /unreturned_private_opening.
  move=> [d [hd [tree sd [ht [hu [hs hv]]]]]].
  exists (hypertree_index d,tree,forest_index d tree); split.
  + exact (ordinary_fors_output_coordinate d tree ht).
  rewrite /unreturned_candidate_guess /observed_private_guess /=.
  split; first exact (unreturned_encoded_input h seed root entries d tree ht hu).
  split; first by rewrite domE hs.
  rewrite hs /= -hv; exact (ordinary_output_candidate_mem output.`2 tree ht).
qed.
