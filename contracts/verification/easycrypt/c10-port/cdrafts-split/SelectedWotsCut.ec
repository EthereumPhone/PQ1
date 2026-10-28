(* Accepted-collision refinement of the actual unreturned-chain cut. *)
require import AllCore List FMap IntDiv RadixEncoding.
require import C10RawOracle RawKeygen RawWots RawForest RawSigner RawCountRecorded.
require import WotsDigitOrder ByteEncodingCharge WotsEncodingSplit WotsCutDisclosure WotsFirstCount.
require import WotsSignatureValue WotsSignWitness VerifierWotsOpening WotsOpeningPersistent WotsChainSplit.
require import ExposureComponents.

require import WotsUnreturnedCut AcceptedWotsCollision C10Counter WotsCountDomain SelectedWotsCollision.

lemma selected_new_bottom_opening_cut h s seed root entries ht message leaf sigma count :
  size seed=32 => !returned_bottom_message h s seed root entries ht message => !selected_accepted_collision h =>
  wots_verifier_opening h s seed 0 (ht %/512) (ht %%512) message leaf (sigma,count) =>
  exists d i, 0<=i<43 /\ 0<=digit 3 d i<7 /\
    h.[wots_count_input seed 0 (ht %/512) (ht %%512) message count]=Some d /\
    nth (nseq 16 0) sigma i=wots_partial h s seed 0 (ht %/512) (ht %%512) i (digit 3 d i) /\
    bottom_cut_unreturned h s seed root entries ht i (digit 3 d i).
proof.
  move=> hs hn he [hr [hc [d [ha [hd [hw hv]]]]]].
  case (exists old, bottom_disclosure h s seed root entries ht old).
  + move=> [old hold].
    have [m sig accepted value lower [hm [hmsg [hi [hf [ho hcold]]]]]] := hold.
    have hvret : returned_bottom_message h s seed root entries ht value
      by exists m sig accepted lower; smt().
    have hdiff : message<>value by smt().
    have [hcount [hrejected [hdold haold]]] := hcold.
    have hcu : 0<=(nth ([],0,[]) sig.`4 0).`2<4294967296 by move: hcount; rewrite /signing_budget; smt().
    have [hbad|[i [hindex hcut]]] := selected_new_message_reverse_or_encoding h seed 0 (ht %/512) (ht %%512)
      message value count (nth ([],0,[]) sig.`4 0).`2 d old hs hc hcu hdiff hd hdold ha haold; first smt().
    exists d i; split; first exact hindex.
    split; first smt(raw_digit_bounds).
    split; first exact hd.
    split; first exact (hv i hindex).
    rewrite /bottom_cut_unreturned; smt(bottom_disclosure_unique).
  move=> hnone.
  have [i [hi hcut]] := accepted_has_nonmax_digit d ha.
  exists d i; rewrite /bottom_cut_unreturned; smt(raw_digit_bounds).
qed.

lemma selected_new_top_opening_cut h s seed root entries tree message leaf sigma count :
  size seed=32 => !returned_top_message h s seed root entries tree message => !selected_accepted_collision h =>
  wots_verifier_opening h s seed 1 0 tree message leaf (sigma,count) =>
  exists d i, 0<=i<43 /\ 0<=digit 3 d i<7 /\
    h.[wots_count_input seed 1 0 tree message count]=Some d /\
    nth (nseq 16 0) sigma i=wots_partial h s seed 1 0 tree i (digit 3 d i) /\
    top_cut_unreturned h s seed root entries tree i (digit 3 d i).
proof.
  move=> hs hn he [hr [hc [d [ha [hd [hw hv]]]]]].
  case (exists old, top_disclosure h s seed root entries tree old).
  + move=> [old hold].
    have [m sig accepted value top [hm [hmsg [hi [hf [ho hcold]]]]]] := hold.
    have hvret : returned_top_message h s seed root entries tree value
      by exists m sig accepted top; smt().
    have hdiff : message<>value by smt().
    have [hcount [hrejected [hdold haold]]] := hcold.
    have hcu : 0<=(nth ([],0,[]) sig.`4 1).`2<4294967296 by move: hcount; rewrite /signing_budget; smt().
    have [hbad|[i [hindex hcut]]] := selected_new_message_reverse_or_encoding h seed 1 0 tree
      message value count (nth ([],0,[]) sig.`4 1).`2 d old hs hc hcu hdiff hd hdold ha haold; first smt().
    exists d i; split; first exact hindex.
    split; first smt(raw_digit_bounds).
    split; first exact hd.
    split; first exact (hv i hindex).
    rewrite /top_cut_unreturned; smt(top_disclosure_unique).
  move=> hnone.
  have [i [hi hcut]] := accepted_has_nonmax_digit d ha.
  exists d i; rewrite /top_cut_unreturned; smt(raw_digit_bounds).
qed.
