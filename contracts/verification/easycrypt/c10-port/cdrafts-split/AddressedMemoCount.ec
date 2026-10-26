(* Count distinct nonordinary public memo keys. Classification is evaluated
   in the current histories; extension can only make old keys ordinary. *)
require import AllCore List FSet FMap.
require import C10RawOracle PersistentGrind AcceptedContexts.
require import AddressedOrdinaryInputs AddressedQueryProvenance.
require import AddressedForsException AddressedForsExceptionCount.

op nonordinary_keys h s seed =
  FSet.filter (fun x => !ordinary_public_input h s seed x) (fdom h).
op nonordinary_count h s seed = card (nonordinary_keys h s seed).

lemma nonordinary_keys_member h s seed x :
  x \in nonordinary_keys h s seed <=> x \in h /\ !ordinary_public_input h s seed x.
proof. rewrite /nonordinary_keys FSet.in_filter mem_fdom; smt(). qed.

lemma nonordinary_count_nonnegative h s seed : 0<=nonordinary_count h s seed.
proof. rewrite /nonordinary_count; exact (fcard_ge0 (nonordinary_keys h s seed)). qed.

lemma nonordinary_count_zero h s seed :
  (forall x, x \in h => ordinary_public_input h s seed x) => nonordinary_count h s seed=0.
proof.
  move=> ho; rewrite /nonordinary_count; apply eq_fcards0; apply in_eq_fset0.
  smt(nonordinary_keys_member).
qed.

lemma nonordinary_count_private_extends h s s' seed :
  extends s s' => nonordinary_count h s' seed<=nonordinary_count h s seed.
proof.
  move=> hs; rewrite /nonordinary_count; apply subset_leq_fcard.
  move=> x; rewrite !nonordinary_keys_member; smt(ordinary_public_input_extends extends_refl).
qed.

lemma nonordinary_count_new_keys h h' s s' seed (charged : raw_input fset) :
  extends h h' => extends s s' =>
  (forall x, x \in h' => x \in h \/ ordinary_public_input h' s' seed x \/ x \in charged) =>
  nonordinary_count h' s' seed<=nonordinary_count h s seed+card charged.
proof.
  move=> hh hs hn.
  have hsub : nonordinary_keys h' s' seed \subset nonordinary_keys h s seed `|` charged.
  + move=> x; rewrite nonordinary_keys_member in_fsetU nonordinary_keys_member.
    smt(ordinary_public_input_extends).
  have hc := subset_leq_fcard _ _ hsub.
  have hu := fcardU (nonordinary_keys h s seed) charged.
  have hz := fcard_ge0 (nonordinary_keys h s seed `&` charged).
  rewrite /nonordinary_count; smt().
qed.

lemma nonordinary_count_insert h s seed x d :
  x \notin h => nonordinary_count h.[x<-d] s seed<=nonordinary_count h s seed+1.
proof.
  move=> hf.
  have hb := nonordinary_count_new_keys h h.[x<-d] s s seed (fset1 x)
    (extends_insert h x d hf) (extends_refl s) _.
  + move=> y; rewrite mem_set in_fset1; smt().
  move: hb; rewrite fcard1; smt().
qed.

lemma nonordinary_count_suffix h h' s s' seed base queries (p : raw_input -> bool) :
  extends h h' => extends s s' => appended_query_history h base h' queries =>
  (forall x, x \in h' => x \in h \/ ordinary_public_input h' s' seed x \/ p x) =>
  nonordinary_count h' s' seed<=nonordinary_count h s seed+
    size (List.filter p queries)-size (List.filter p base).
proof.
  move=> hh hs [inputs [hq hi]] hn.
  have hb := nonordinary_count_new_keys h h' s s' seed (oflist (List.filter p inputs)) hh hs _.
  + move=> x hx; rewrite mem_oflist List.mem_filter; smt().
  have hc := fcard_oflist (List.filter p inputs).
  rewrite hq List.filter_cat size_cat; smt().
qed.

lemma nonordinary_count_sign_suffix h h' s s' seed base queries :
  extends h h' => extends s s' => appended_query_history h base h' queries =>
  ordinary_new_inputs h h' s' seed =>
  nonordinary_count h' s' seed<=nonordinary_count h s seed+
    exceptional_fors_count queries-exceptional_fors_count base.
proof.
  rewrite /ordinary_new_inputs /exceptional_fors_count.
  exact (nonordinary_count_suffix h h' s s' seed base queries exceptional_fors_query).
qed.

lemma nonordinary_count_public_suffix h h' s s' seed base queries :
  extends h h' => extends s s' => appended_query_history h base h' queries =>
  nonordinary_count h' s' seed<=nonordinary_count h s seed+size queries-size base.
proof.
  move=> hh hs hp.
  have hb := nonordinary_count_suffix h h' s s' seed base queries predT hh hs hp _; first smt().
  move: hb; rewrite !List.filter_predT; smt().
qed.
