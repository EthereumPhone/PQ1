(* Exact memo-table buckets: no repeated cached entry is a new sample. *)
require import AllCore List FSet FMap.
require import C10RawOracle RawKeygen PersistentGrind AcceptedContexts.
require import AddressedNodeCollision AddressedBuckets.

op addressed_hits h label = List.map (fun x => node (oget h.[x])) (elems (addressed_bucket h label)).
op label_collision (h : (raw_input,digest) fmap) =
  exists x y, x<>y /\ x \in h /\ y \in h /\ addressed_label x=addressed_label y /\
    node (oget h.[x])=node (oget h.[y]).
op oversized_bucket h cap = exists label, cap<card (addressed_bucket h label).

lemma addressed_hits_size h label : size (addressed_hits h label)=card (addressed_bucket h label).
proof. by rewrite /addressed_hits size_map -cardE. qed.

lemma addressed_hits_member h label value :
  value \in addressed_hits h label <=>
    exists x, x \in h /\ addressed_label x=label /\ node (oget h.[x])=value.
proof.
  rewrite /addressed_hits mapP; split.
  + move=> [x [hx he]]; exists x; move: hx; rewrite -memE addressed_bucket_member; smt().
  move=> [x [#] hx hl hv]; exists x; rewrite -memE addressed_bucket_member; smt().
qed.

lemma addressed_bucket_empty h label :
  addressed_bucket h label=fset0 <=> label \notin addressed_labels h.
proof.
  rewrite fsetP /addressed_labels imageP; split.
  + move=> hb; smt(addressed_bucket_member mem_fdom in_fset0).
  move=> hb x; rewrite addressed_bucket_member in_fset0; smt(mem_fdom).
qed.

lemma addressed_hits_positive h label :
  0<size (addressed_hits h label) <=> label \in addressed_labels h.
proof.
  rewrite addressed_hits_size; have hz := fcard_ge0 (addressed_bucket h label).
  have he := fcard_eq0 (addressed_bucket h label).
  have hb := addressed_bucket_empty h label; smt().
qed.

lemma addressed_hits_member_positive h label value :
  value \in addressed_hits h label => 0<size (addressed_hits h label).
proof. smt(List.size_eq0 List.size_ge0 List.in_nil). qed.

lemma addressed_bucket_extends h h' label :
  extends h h' => addressed_bucket h label \subset addressed_bucket h' label.
proof. rewrite /extends => hh x; rewrite !addressed_bucket_member; smt(domE). qed.

lemma oversized_bucket_extends h h' cap :
  extends h h' => oversized_bucket h cap => oversized_bucket h' cap.
proof.
  move=> hh [label hl]; exists label.
  have hb := subset_leq_fcard _ _ (addressed_bucket_extends h h' label hh); smt().
qed.

lemma addressed_collision_label h : addressed_node_collision h => label_collision h.
proof.
  move=> [x y dx dy [#] hx hy hl hd hdx hdy he]; exists x y.
  smt(addressed_label_node domE).
qed.

lemma label_collision_empty : !label_collision empty.
proof. rewrite /label_collision; smt(mem_empty). qed.

lemma label_collision_insert h x d :
  x \notin h => label_collision h.[x<-d] =>
  label_collision h \/ node d \in addressed_hits h (addressed_label x).
proof.
  move=> hf [y z [#] hd hy hz hl hn].
  case (y=x) => he.
  + right; rewrite addressed_hits_member; exists z; smt(mem_set get_setE).
  case (z=x) => he'.
  + right; rewrite addressed_hits_member; exists y; smt(mem_set get_setE).
  left; exists y z; smt(mem_set get_setE).
qed.

lemma addressed_insert_coverage h x d cap bad :
  x \notin h => (label_collision h => bad \/ oversized_bucket h cap) =>
  (label_collision h.[x<-d] =>
    (bad \/ (0<size (addressed_hits h (addressed_label x)) /\
      size (addressed_hits h (addressed_label x))<=cap /\
      node d \in addressed_hits h (addressed_label x))) \/ oversized_bucket h.[x<-d] cap).
proof.
  move=> hf hi hc.
  have hh := extends_insert h x d hf.
  have hn := label_collision_insert h x d hf hc.
  case (label_collision h) => ho; first smt(oversized_bucket_extends).
  case (size (addressed_hits h (addressed_label x))<=cap) => hs.
  + smt(addressed_hits_member_positive).
  right; apply (oversized_bucket_extends h h.[x<-d] cap hh).
  exists (addressed_label x); smt(addressed_hits_size).
qed.
