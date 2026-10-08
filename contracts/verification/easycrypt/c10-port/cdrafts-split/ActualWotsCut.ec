(* The WOTS residual retains a concrete node from the actual verifier output. *)
require import AllCore List FMap IntDiv RadixEncoding.
require import C10RawOracle C10HashDomains RawKeygen RawWots RawForest RawSigner RawSignature.
require import WotsReference WotsReferenceRoot WotsChainSplit VerifierWotsOpening.
require import WotsUnreturnedCut ByteEncodingCharge ExposureComponents ForestOpeningCases.
require import ExposurePartition ExposureCoverage ActualExposurePartition ActualForsOpening.

op actual_top_cut h s seed root entries (output : raw_input * raw_signature) =
  exists accepted i cut,
    h.[hmsg_input seed root (pad output.`2.`1) output.`1]=Some accepted /\
    0<=i<43 /\ 0<=cut<7 /\
    wots_prefix h s seed 1 0 (hypertree_index accepted %/512) 43 /\
    nth (nseq 16 0) (nth ([],0,[]) output.`2.`4 1).`1 i=
      wots_partial h s seed 1 0 (hypertree_index accepted %/512) i cut /\
    top_cut_unreturned h s seed root entries (hypertree_index accepted %/512) i cut.

op actual_bottom_cut h s seed root entries (output : raw_input * raw_signature) =
  exists accepted i cut,
    h.[hmsg_input seed root (pad output.`2.`1) output.`1]=Some accepted /\
    0<=i<43 /\ 0<=cut<7 /\
    wots_prefix h s seed 0 (hypertree_index accepted %/512) (hypertree_index accepted %%512) 43 /\
    nth (nseq 16 0) (nth ([],0,[]) output.`2.`4 0).`1 i=
      wots_partial h s seed 0 (hypertree_index accepted %/512) (hypertree_index accepted %%512) i cut /\
    bottom_cut_unreturned h s seed root entries (hypertree_index accepted) i cut.

lemma actual_new_top_cut h s seed root entries (output : raw_input * raw_signature) accepted :
  h.[hmsg_input seed root (pad output.`2.`1) output.`1]=Some accepted =>
  new_top_component h s seed root entries accepted output.`2 => !wots_encoding_collision h =>
  actual_top_cut h s seed root entries output.
proof.
  move=> hd [message leaf [hn ho]] he.
  have [d i [hi [hc [hdc [hv hu]]]]] := new_top_opening_cut h s seed root entries
    (hypertree_index accepted %/512) message leaf (nth ([],0,[]) output.`2.`4 1).`1
    (nth ([],0,[]) output.`2.`4 1).`2 hn he ho.
  exists accepted i (digit 3 d i); move: ho; rewrite /wots_verifier_opening /wots_root; smt().
qed.

lemma actual_new_bottom_cut h s seed root entries (output : raw_input * raw_signature) accepted :
  h.[hmsg_input seed root (pad output.`2.`1) output.`1]=Some accepted =>
  new_bottom_component h s seed root entries accepted output.`2 => !wots_encoding_collision h =>
  actual_bottom_cut h s seed root entries output.
proof.
  move=> hd [message lower leaf top [hl hn]] he.
  have ho : wots_verifier_opening h s seed 0 (hypertree_index accepted %/512) (hypertree_index accepted %%512)
    message leaf ((nth ([],0,[]) output.`2.`4 0).`1,(nth ([],0,[]) output.`2.`4 0).`2)
    by move: hl; rewrite /linked_forest_layers; smt().
  have [d i [hi [hc [hdc [hv hu]]]]] := new_bottom_opening_cut h s seed root entries
    (hypertree_index accepted) message leaf (nth ([],0,[]) output.`2.`4 0).`1
    (nth ([],0,[]) output.`2.`4 0).`2 hn he ho.
  exists accepted i (digit 3 d i); move: ho; rewrite /wots_verifier_opening /wots_root; smt().
qed.

op actual_covered_output h seed root entries (output : raw_input * raw_signature) =
  exists d, h.[hmsg_input seed root (pad output.`2.`1) output.`1]=Some d /\
    returned_coverage h seed root entries d.

lemma actual_partition_cut_cases h s seed root entries output :
  actual_exposure_partition h s seed root entries output =>
  wots_encoding_collision h \/ actual_top_cut h s seed root entries output \/
    actual_bottom_cut h s seed root entries output \/ actual_output_unreturned h s seed root entries output \/
    actual_covered_output h seed root entries output.
proof.
  move=> [hm [hs [hn [accepted [ha [hd hc]]]]]].
  case (wots_encoding_collision h) => he; first smt().
  have [ht|[hb|[hf|hr]]] := hc.
  + have ht' := actual_new_top_cut h s seed root entries output accepted hd ht he; smt().
  + have hb' := actual_new_bottom_cut h s seed root entries output accepted hd hb he; smt().
  + have hf' : actual_output_unreturned h s seed root entries output by exists accepted; smt().
    smt().
  have hr' : actual_covered_output h seed root entries output by exists accepted; smt().
  smt().
qed.
