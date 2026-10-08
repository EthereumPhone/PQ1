(* A valid new component supplies a chain cut below every returned signature. *)
require import AllCore List FMap IntDiv RadixEncoding.
require import C10RawOracle RawKeygen RawWots RawForest RawSigner RawCountRecorded.
require import WotsDigitOrder ByteEncodingCharge WotsEncodingSplit WotsCutDisclosure WotsFirstCount.
require import WotsSignatureValue WotsSignWitness VerifierWotsOpening WotsOpeningPersistent WotsChainSplit.
require import ExposureComponents.

lemma constant_sum n z : 0<=n => sumz (nseq n z)=n*z.
proof.
  move=> hn; elim: n hn => [|n hn ih].
  + by rewrite nseq0 /sumz /=.
  rewrite nseqS 1:hn /sumz /= -/(sumz _) ih; smt().
qed.

lemma accepted_has_nonmax_digit d :
  count_accepts d => exists i, 0<=i<43 /\ digit 3 d i<7.
proof.
  move=> ha; case (exists i, 0<=i<43 /\ digit 3 d i<7); first smt().
  move=> hn.
  have he : raw_digits d=nseq 43 7.
  + apply (eq_from_nth 0); first by rewrite /raw_digits /digits size_mkseq size_nseq.
    move=> i; rewrite /raw_digits /digits size_mkseq /= => hi.
    rewrite nth_mkseq 1:hi nth_nseq; smt(raw_digit_bounds).
  move: ha; rewrite /count_accepts he constant_sum 1://; smt().
qed.

op bottom_cut_unreturned h s seed root entries ht i cut =
  forall d, bottom_disclosure h s seed root entries ht d => cut<digit 3 d i.
op top_cut_unreturned h s seed root entries tree i cut =
  forall d, top_disclosure h s seed root entries tree d => cut<digit 3 d i.

lemma new_bottom_opening_cut h s seed root entries ht message leaf sigma count :
  !returned_bottom_message h s seed root entries ht message => !wots_encoding_collision h =>
  wots_verifier_opening h s seed 0 (ht %/512) (ht %%512) message leaf (sigma,count) =>
  exists d i, 0<=i<43 /\ 0<=digit 3 d i<7 /\
    h.[wots_count_input seed 0 (ht %/512) (ht %%512) message count]=Some d /\
    nth (nseq 16 0) sigma i=wots_partial h s seed 0 (ht %/512) (ht %%512) i (digit 3 d i) /\
    bottom_cut_unreturned h s seed root entries ht i (digit 3 d i).
proof.
  move=> hn he [hr [hc [d [ha [hd [hw hv]]]]]].
  case (exists old, bottom_disclosure h s seed root entries ht old).
  + move=> [old hold].
    have [m sig accepted value lower [hm [hmsg [hi [hf [ho hcold]]]]]] := hold.
    have hvret : returned_bottom_message h s seed root entries ht value
      by exists m sig accepted lower; smt().
    have hdiff : message<>value by smt().
    have [hcount [hrejected [hdold haold]]] := hcold.
    have [hbad|[i [hindex hcut]]] := new_message_reverse_or_encoding h seed 0 (ht %/512) (ht %%512)
      message value count (nth ([],0,[]) sig.`4 0).`2 d old hdiff hd hdold ha haold; first smt().
    exists d i; split; first exact hindex.
    split; first smt(raw_digit_bounds).
    split; first exact hd.
    split; first exact (hv i hindex).
    rewrite /bottom_cut_unreturned; smt(bottom_disclosure_unique).
  move=> hnone.
  have [i [hi hcut]] := accepted_has_nonmax_digit d ha.
  exists d i; rewrite /bottom_cut_unreturned; smt(raw_digit_bounds).
qed.

lemma new_top_opening_cut h s seed root entries tree message leaf sigma count :
  !returned_top_message h s seed root entries tree message => !wots_encoding_collision h =>
  wots_verifier_opening h s seed 1 0 tree message leaf (sigma,count) =>
  exists d i, 0<=i<43 /\ 0<=digit 3 d i<7 /\
    h.[wots_count_input seed 1 0 tree message count]=Some d /\
    nth (nseq 16 0) sigma i=wots_partial h s seed 1 0 tree i (digit 3 d i) /\
    top_cut_unreturned h s seed root entries tree i (digit 3 d i).
proof.
  move=> hn he [hr [hc [d [ha [hd [hw hv]]]]]].
  case (exists old, top_disclosure h s seed root entries tree old).
  + move=> [old hold].
    have [m sig accepted value top [hm [hmsg [hi [hf [ho hcold]]]]]] := hold.
    have hvret : returned_top_message h s seed root entries tree value
      by exists m sig accepted top; smt().
    have hdiff : message<>value by smt().
    have [hcount [hrejected [hdold haold]]] := hcold.
    have [hbad|[i [hindex hcut]]] := new_message_reverse_or_encoding h seed 1 0 tree
      message value count (nth ([],0,[]) sig.`4 1).`2 d old hdiff hd hdold ha haold; first smt().
    exists d i; split; first exact hindex.
    split; first smt(raw_digit_bounds).
    split; first exact hd.
    split; first exact (hv i hindex).
    rewrite /top_cut_unreturned; smt(top_disclosure_unique).
  move=> hnone.
  have [i [hi hcut]] := accepted_has_nonmax_digit d ha.
  exists d i; rewrite /top_cut_unreturned; smt(raw_digit_bounds).
qed.
