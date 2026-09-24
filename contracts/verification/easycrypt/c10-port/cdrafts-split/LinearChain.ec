(* Recorded evaluation of a sequence of actual raw WOTS chain steps. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen PersistentGrind AcceptedContexts.

op linear_step (h : (raw_input,digest) fmap)
    (f : int -> raw_input -> raw_input) (value : raw_input) index =
  node (oget h.[f index value]).
op linear_value h f value (indices : int list) = foldl (linear_step h f) value indices.
op linear_recorded (h : (raw_input,digest) fmap) f (value : raw_input) (indices : int list) =
  with indices = [] => true
  with indices = index :: rest =>
    f index value \in h /\ linear_recorded h f (linear_step h f value index) rest.

lemma linear_value_rcons h f value indices index :
  linear_value h f value (rcons indices index) =
    linear_step h f (linear_value h f value indices) index.
proof. by rewrite /linear_value foldl_rcons. qed.

lemma linear_recorded_rcons h f value indices index :
  linear_recorded h f value indices =>
  f index (linear_value h f value indices) \in h =>
  linear_recorded h f value (rcons indices index).
proof.
  elim: indices value => [value /= | x xs ih value /=].
  + rewrite /linear_value /=; smt().
  rewrite /linear_value /= => [#] hx hp hy.
  split; first exact hx.
  exact (ih _ hp hy).
qed.

lemma linear_step_extends h h' f value index :
  extends h h' => f index value \in h =>
  linear_step h' f value index = linear_step h f value index.
proof. rewrite /extends /linear_step; smt(). qed.

lemma linear_recorded_extends h h' f value indices :
  extends h h' => linear_recorded h f value indices =>
  linear_recorded h' f value indices /\
    linear_value h' f value indices = linear_value h f value indices.
proof.
  move=> he; elim: indices value => [value /= | x xs ih value /=].
  + by rewrite /linear_value /=.
  move=> [hx hp].
  have hs := linear_step_extends h h' f value x he hx.
  have [hr hv] := ih _ hp.
  split.
  + split; last by rewrite hs.
    move: he hx; rewrite /extends; smt(domE).
  by rewrite /linear_value /= hs.
qed.

lemma linear_recorded_step h f value indices index d output :
  linear_recorded h f value indices => linear_value h f value indices = output =>
  h.[f index output] = Some d =>
  linear_recorded h f value (rcons indices index) /\
    linear_value h f value (rcons indices index) = node d.
proof.
  move=> hr hv hd; split.
  + apply linear_recorded_rcons => //; smt(domE).
  by rewrite linear_value_rcons hv /linear_step hd oget_some.
qed.

lemma linear_value_cat h f value prefix suffix :
  linear_value h f value (prefix ++ suffix) =
    linear_value h f (linear_value h f value prefix) suffix.
proof. by rewrite /linear_value foldl_cat. qed.

lemma linear_recorded_cat h f value prefix suffix :
  linear_recorded h f value (prefix ++ suffix) <=>
    linear_recorded h f value prefix /\
    linear_recorded h f (linear_value h f value prefix) suffix.
proof.
  elim: prefix value => [value /= | x xs ih value /=].
  + by rewrite /linear_value /=.
  rewrite /linear_value /=; smt().
qed.
