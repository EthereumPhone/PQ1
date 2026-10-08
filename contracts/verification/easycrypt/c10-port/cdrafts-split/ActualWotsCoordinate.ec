(* A union over fixed coordinates covers every retained actual-output WOTS cut. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen RawForest RawSigner.
require import WotsReference WotsChainSplit WotsUnreturnedCut ActualWotsCut.
require import WotsCoordinateUniverse ChainByteCandidates.

op selected_wots_cut h s seed root entries outputs (c : wots_coordinate) =
  wots_prefix h s seed c.`1 c.`2 c.`3 43 /\
  mem outputs (wots_partial h s seed c.`1 c.`2 c.`3 c.`4 c.`5) /\
  (if c.`1=0 then bottom_cut_unreturned h s seed root entries (512*c.`2+c.`3) c.`4 c.`5
    else top_cut_unreturned h s seed root entries c.`3 c.`4 c.`5).

lemma actual_top_coordinate h s seed root entries output :
  actual_top_cut h s seed root entries output =>
  exists c, mem wots_coordinates c /\
    selected_wots_cut h s seed root entries (wots_output_candidates output.`2) c.
proof.
  move=> [d i cut [hd [hi [hc [hp [hv hu]]]]]].
  exists (1,0,hypertree_index d %/512,i,cut); split.
  + exact (top_output_coordinate d i cut hi hc).
  rewrite /selected_wots_cut /=; split; first exact hp.
  split; last exact hu.
  rewrite -hv; apply (wots_output_candidate_mem output.`2 1 i); smt().
qed.
lemma actual_bottom_coordinate h s seed root entries output :
  actual_bottom_cut h s seed root entries output =>
  exists c, mem wots_coordinates c /\
    selected_wots_cut h s seed root entries (wots_output_candidates output.`2) c.
proof.
  move=> [d i cut [hd [hi [hc [hp [hv hu]]]]]].
  exists (0,hypertree_index d %/512,hypertree_index d %%512,i,cut); split.
  + exact (bottom_output_coordinate d i cut hi hc).
  rewrite /selected_wots_cut /=; split; first exact hp.
  split.
  + rewrite -hv; apply (wots_output_candidate_mem output.`2 0 i); smt().
  have he : 512*(hypertree_index d %/512)+hypertree_index d %%512=hypertree_index d by smt(divz_eq).
  by rewrite he.
qed.
