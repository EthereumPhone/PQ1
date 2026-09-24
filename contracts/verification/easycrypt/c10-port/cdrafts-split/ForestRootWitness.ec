(* Complete forest references include the special thirteenth root-as-secret. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawSignature RawForest PersistentGrind.
require import ForsRootWitness ForestWitness.

op forest_root_witness h s seed ht root =
  exists roots lastroot special final,
    rows_width 13 roots /\
    (forall t, 0<=t<12 => fors_root_witness h s seed ht t (nth (nseq 16 0) roots t)) /\
    fors_root_witness h s seed ht 12 lastroot /\
    h.[forest_special_input seed ht lastroot]=Some special /\
    nth (nseq 16 0) roots 12=node special /\
    h.[forest_compress_input seed ht roots]=Some final /\ root=node final.

lemma forest_root_witness_extends h h' s s' seed ht root :
  extends h h' => extends s s' => forest_root_witness h s seed ht root =>
  forest_root_witness h' s' seed ht root.
proof.
  move=> hh hs [roots lastroot special final [hw [hf [hl [he [hr [hc hv]]]]]]].
  exists roots lastroot special final.
  have hf' : forall t, 0<=t<12 => fors_root_witness h' s' seed ht t (nth (nseq 16 0) roots t)
    by smt(fors_root_witness_extends).
  have hl' := fors_root_witness_extends h h' s s' seed ht 12 lastroot hh hs hl.
  move: hh; rewrite /extends; smt().
qed.

lemma forest_root_compressed_extends h h' s s' seed ht roots lastroot special final :
  extends h h' => extends s s' => rows_width 13 roots =>
  (forall t, 0<=t<12 => fors_root_witness h s seed ht t (nth (nseq 16 0) roots t)) =>
  fors_root_witness h s seed ht 12 lastroot =>
  h.[forest_special_input seed ht lastroot]=Some special =>
  nth (nseq 16 0) roots 12=node special =>
  h'.[forest_compress_input seed ht roots]=Some final =>
  forest_root_witness h' s' seed ht (node final).
proof.
  move=> hh hs hw hf hl he hr hc.
  have hf' : forall t, 0<=t<12 => fors_root_witness h' s' seed ht t (nth (nseq 16 0) roots t)
    by smt(fors_root_witness_extends).
  have hl' := fors_root_witness_extends h h' s s' seed ht 12 lastroot hh hs hl.
  exists roots lastroot special final; move: hh; rewrite /extends; smt().
qed.

op forest_private_openings h s seed ht digest (secrets : raw_input list) =
  (forall t, 0<=t<12 => exists sd,
    s.[ForsPrivateLeaves.fors_private_key ht t (forest_index digest t)]=Some sd /\
    nth (nseq 16 0) secrets t=node sd) /\
  fors_root_witness h s seed ht 12 (nth (nseq 16 0) secrets 12).

lemma forest_private_openings_extends h h' s s' seed ht digest secrets :
  extends h h' => extends s s' => forest_private_openings h s seed ht digest secrets =>
  forest_private_openings h' s' seed ht digest secrets.
proof.
  move=> hh hs [hp hl]; split.
  + move: hs; rewrite /extends; smt().
  exact (fors_root_witness_extends h h' s s' seed ht 12 (nth (nseq 16 0) secrets 12) hh hs hl).
qed.
