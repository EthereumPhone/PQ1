(* The final forest compression input is determined before its hash call.
   Its special last component is retained explicitly, not replaced by a leaf. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawSignature RawForest ForestWitness.
require import PersistentGrind AcceptedContexts ForsRootWitness ForsRootDeterminism.
require import ClientGuessCandidates AddressedInputFields AddressedNodeCollision AddressedInputKinds.

op canonical_forest_roots h s seed ht roots =
  rows_width 13 roots /\
  (forall t, 0<=t<12 => fors_root_witness h s seed ht t (nth (nseq 16 0) roots t)) /\
  exists lastroot special, fors_root_witness h s seed ht 12 lastroot /\
    h.[forest_special_input seed ht lastroot]=Some special /\ nth (nseq 16 0) roots 12=node special.

lemma canonical_forest_roots_extends h h' s s' seed ht roots :
  extends h h' => extends s s' => canonical_forest_roots h s seed ht roots =>
  canonical_forest_roots h' s' seed ht roots.
proof.
  move=> hh hs [hw [hf [lastroot special [hl [he hr]]]]].
  rewrite /canonical_forest_roots; split; first exact hw.
  split; first smt(fors_root_witness_extends).
  exists lastroot special.
  have hl' := fors_root_witness_extends h h' s s' seed ht 12 lastroot hh hs hl.
  move: hh; rewrite /extends; smt().
qed.

lemma canonical_forest_roots_unique h s seed ht roots roots' :
  canonical_forest_roots h s seed ht roots => canonical_forest_roots h s seed ht roots' => roots=roots'.
proof.
  move=> [hw [hf [lastroot special [hl [he hr]]]]]
    [hw' [hf' [lastroot' special' [hl' [he' hr']]]]].
  have hl_eq := fors_root_witness_unique h s seed ht 12 lastroot lastroot' hl hl'.
  have special_eq : special=special' by smt().
  apply (eq_from_nth (nseq 16 0)); first by move: hw hw'; rewrite /rows_width; smt().
  move=> i hi; have hi' : 0<=i<13 by move: hw hi; rewrite /rows_width; smt().
  case (i<12) => hit.
  + have hit' : 0<=i<12 by smt().
    exact (fors_root_witness_unique h s seed ht i _ _ (hf i hit') (hf' i hit')).
  have -> : i=12 by smt().
  smt().
qed.

op canonical_forest_input h s seed x =
  exists ht roots, 0<=ht<2^64 /\ canonical_forest_roots h s seed ht roots /\
    x=forest_compress_input seed ht roots.

lemma canonical_forest_input_extends h h' s s' seed x :
  extends h h' => extends s s' => canonical_forest_input h s seed x =>
  canonical_forest_input h' s' seed x.
proof.
  move=> hh hs [ht roots [hv [hc hx]]]; exists ht roots.
  smt(canonical_forest_roots_extends).
qed.

lemma canonical_forest_input_unique h s seed x y :
  size seed=32 => canonical_forest_input h s seed x => canonical_forest_input h s seed y =>
  same_node_address x y => x=y.
proof.
  move=> hs [ht roots [hv [hc hx]]] [ht' roots' [hv' [hc' hy]]] he.
  have hp : same_node_address (seed++address 0 ht 4 0 0 0 0++flatten (map pad roots))
    (seed++address 0 ht' 4 0 0 0 0++flatten (map pad roots'))
    by move: he; rewrite hx hy /forest_compress_input.
  have ha : address 0 ht 4 0 0 0 0=address 0 ht' 4 0 0 0 0
    by have hh := addressed_prefix_coordinates seed (address 0 ht 4 0 0 0 0) _
      seed (address 0 ht' 4 0 0 0 0) _ hs hs
      (raw_address_width _ _ _ _ _ _ _) (raw_address_width _ _ _ _ _ _ _) hp; smt().
  have hf := address_fields_injective 0 ht 4 0 0 0 0 0 ht' 4 0 0 0 0.
  have ht_eq : ht=ht' by smt().
  have hr_eq := canonical_forest_roots_unique h s seed ht roots roots' hc _; first smt().
  smt().
qed.

lemma canonical_forest_kind h s seed x :
  size seed=32 => canonical_forest_input h s seed x => public_address_kind x=be 4 4.
proof.
  move=> hs [ht roots [hv [hc hx]]]; rewrite hx /forest_compress_input.
  exact (public_address_kind_input _ _ _ _ _ _ _ _ _ hs).
qed.
