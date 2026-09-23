(* Recorded bottom-up path evaluation in one memoized public table. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen PersistentGrind AcceptedContexts.

type path_state = raw_input * int * int.

op path_input (f : int -> int -> raw_input -> raw_input -> raw_input)
  (st : path_state) (sibling : raw_input) =
  f (st.`2+1) (st.`3 %/ 2)
    (if st.`3 %% 2 = 0 then st.`1 else sibling)
    (if st.`3 %% 2 = 0 then sibling else st.`1).

op path_step (h : (raw_input,digest) fmap) f (st : path_state) sibling =
  (node (oget h.[path_input f st sibling]), st.`2+1, st.`3 %/ 2).

op path_value h f st auth = foldl (path_step h f) st auth.

op path_recorded (h : (raw_input,digest) fmap) f (st : path_state)
  (auth : raw_input list) =
  with auth = [] => true
  with auth = sibling :: rest =>
    path_input f st sibling \in h /\
    path_recorded h f (path_step h f st sibling) rest.

lemma path_value_rcons h f st auth sibling :
  path_value h f st (rcons auth sibling) =
  path_step h f (path_value h f st auth) sibling.
proof. by rewrite /path_value foldl_rcons. qed.

lemma path_recorded_rcons h f st auth sibling :
  path_recorded h f st auth =>
  path_input f (path_value h f st auth) sibling \in h =>
  path_recorded h f st (rcons auth sibling).
proof.
  elim: auth st => [st /= | x xs ih st /=].
  + rewrite /path_value /=; smt().
  rewrite /path_value /= => [#] hx hp hy.
  split; first exact hx.
  exact (ih _ hp hy).
qed.

lemma path_step_extends h h' f st sibling :
  extends h h' => path_input f st sibling \in h =>
  path_step h' f st sibling = path_step h f st sibling.
proof. rewrite /extends /path_step; smt(). qed.

lemma path_recorded_extends h h' f st auth :
  extends h h' => path_recorded h f st auth =>
  path_recorded h' f st auth /\
  path_value h' f st auth = path_value h f st auth.
proof.
  move=> he; elim: auth st => [st /= | x xs ih st /=].
  + by rewrite /path_value /=.
  move=> [hx hp].
  have hs := path_step_extends h h' f st x he hx.
  have [hr hv] := ih _ hp.
  split.
  + split; last by rewrite hs.
    move: he hx; rewrite /extends; smt(domE).
  by rewrite /path_value /= hs.
qed.

lemma path_recorded_step h f st auth sibling d value :
  path_recorded h f st auth =>
  path_value h f st auth = value =>
  h.[path_input f value sibling] = Some d =>
  path_recorded h f st (rcons auth sibling) /\
  path_value h f st (rcons auth sibling) =
    (node d,value.`2+1,value.`3 %/ 2).
proof.
  move=> hr hv hd; split.
  + apply path_recorded_rcons => //; smt(domE).
  by rewrite path_value_rcons hv /path_step hd oget_some.
qed.
