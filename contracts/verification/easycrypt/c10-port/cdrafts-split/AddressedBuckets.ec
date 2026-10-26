(* Prefix labels for node queries, exact-key labels for all other inputs.
   Distinct memo keys give one first draw per label; all further draws count. *)
require import AllCore List FSet FMap.
require import C10RawOracle NodeQueryDomain AddressedNodeCollision.
require import AddressedOrdinaryInputs AddressedMemoCount.

op addressed_label (x : raw_input) = if node_query x then 1::take 64 x else 0::x.
op addressed_labels (h : (raw_input,digest) fmap) = image addressed_label (fdom h).
op addressed_bucket (h : (raw_input,digest) fmap) label =
  FSet.filter (fun x => addressed_label x=label) (fdom h).
op addressed_excess (h : (raw_input,digest) fmap) = card (fdom h)-card (addressed_labels h).
op ordinary_keys h s seed = FSet.filter (ordinary_public_input h s seed) (fdom h).

lemma addressed_label_node x y :
  node_query x => node_query y =>
  (addressed_label x=addressed_label y <=> same_node_address x y).
proof. rewrite /addressed_label /same_node_address; smt(). qed.

lemma addressed_label_ordinary_injective h s seed x y :
  size seed=32 => ordinary_public_input h s seed x => ordinary_public_input h s seed y =>
  addressed_label x=addressed_label y => x=y.
proof.
  move=> hs hx hy; rewrite /addressed_label.
  case (node_query x) => hn; case (node_query y) => hm; simplify; smt(ordinary_public_node_unique).
qed.

lemma addressed_bucket_member h label x :
  x \in addressed_bucket h label <=> x \in h /\ addressed_label x=label.
proof. rewrite /addressed_bucket FSet.in_filter mem_fdom; smt(). qed.

lemma ordinary_keys_member h s seed x :
  x \in ordinary_keys h s seed <=> x \in h /\ ordinary_public_input h s seed x.
proof. rewrite /ordinary_keys FSet.in_filter mem_fdom; smt(). qed.

lemma addressed_bucket_bound h s seed label :
  size seed=32 => card (addressed_bucket h label)<=nonordinary_count h s seed+1.
proof.
  move=> hs; case (exists x, x \in addressed_bucket h label /\ ordinary_public_input h s seed x).
  + move=> [x [hx ho]].
    have hsub : addressed_bucket h label \subset nonordinary_keys h s seed `|` fset1 x.
    + move=> y; rewrite addressed_bucket_member in_fsetU nonordinary_keys_member in_fset1.
      move: hx; rewrite addressed_bucket_member; smt(addressed_label_ordinary_injective).
    have hb := subset_leq_fcard _ _ hsub.
    have hu := fcardU1 (nonordinary_keys h s seed) x.
    rewrite /nonordinary_count; smt(b2i_le1).
  move=> hn.
  have hsub : addressed_bucket h label \subset nonordinary_keys h s seed.
  + move=> x; rewrite nonordinary_keys_member; smt(addressed_bucket_member).
  have hb := subset_leq_fcard _ _ hsub; rewrite /nonordinary_count; smt().
qed.

lemma ordinary_keys_card h s seed :
  card (fdom h)=card (ordinary_keys h s seed)+nonordinary_count h s seed.
proof.
  have hu : ordinary_keys h s seed `|` nonordinary_keys h s seed=fdom h.
  + apply fsetP; move=> x; rewrite in_fsetU ordinary_keys_member nonordinary_keys_member mem_fdom; smt().
  have hi : ordinary_keys h s seed `&` nonordinary_keys h s seed=fset0.
  + apply fsetP; move=> x; rewrite in_fsetI ordinary_keys_member nonordinary_keys_member in_fset0; smt().
  have hc := fcardUI_indep _ _ hi; move: hc; rewrite hu /nonordinary_count; smt().
qed.

lemma addressed_ordinary_label_card h s seed :
  size seed=32 => card (image addressed_label (ordinary_keys h s seed))=card (ordinary_keys h s seed).
proof.
  move=> hs; rewrite imageE uniq_card_oflist.
  + apply map_inj_in_uniq.
    + move=> x y; rewrite -!FSet.memE !ordinary_keys_member;
        smt(addressed_label_ordinary_injective).
    exact (uniq_elems (ordinary_keys h s seed)).
  by rewrite size_map -cardE.
qed.

lemma addressed_excess_nonnegative h : 0<=addressed_excess h.
proof. rewrite /addressed_excess /addressed_labels; smt(fcard_image_leq). qed.

lemma addressed_excess_bound h s seed :
  size seed=32 => addressed_excess h<=nonordinary_count h s seed.
proof.
  move=> hs.
  have hsub : image addressed_label (ordinary_keys h s seed) \subset addressed_labels h.
  + move=> label; rewrite /addressed_labels !imageP.
    move=> [x [hx he]]; exists x; move: hx; rewrite ordinary_keys_member mem_fdom; smt().
  have hb := subset_leq_fcard _ _ hsub.
  have hc := addressed_ordinary_label_card h s seed hs.
  have hp := ordinary_keys_card h s seed.
  rewrite /addressed_excess; smt().
qed.

lemma addressed_excess_empty : addressed_excess empty=0.
proof. rewrite /addressed_excess /addressed_labels fdom0 image0 !fcards0; smt(). qed.

lemma addressed_excess_insert h x d :
  x \notin h => addressed_excess h.[x<-d]=addressed_excess h+b2i (addressed_label x \in addressed_labels h).
proof.
  move=> hf; rewrite /addressed_excess /addressed_labels fdom_set imageU image1 !fcardU1 mem_fdom hf /=.
  case (addressed_label x \in image addressed_label (fdom h)); smt().
qed.
