require import AllCore List FMap C10RawOracle PrefixGuess KeygenPrefixes.

(* Deterministic functional interpretation, separate from the random oracle.
   Arbitrary prior history is retained and must agree with the same backend.
   This is not a claim about concrete SHA security or a RO simulation. *)


op backend_consistent (h : (raw_input,digest) fmap) (f : raw_input -> digest) =
  forall x y, h.[x] = Some y => y = f x.

op remember (h : (raw_input,digest) fmap) x y =
  if x \in h then h else h.[x <- y].

op backend_history (f : raw_input -> digest) h (queries : raw_input list) =
  foldl (fun table x => remember table x (f x)) h queries.













module FixedBackend = {
  var fn : raw_input -> digest
  var history : (raw_input,digest) fmap
  var calls : int

  proc init(f : raw_input -> digest) : unit = {
    fn <- f; history <- empty; calls <- 0;
  }
  proc hash(x : raw_input) : digest = {
    calls <- calls + 2;
    if (x \notin history) { history.[x] <- fn x; }
    return oget history.[x];
  }
}.

module FixedPrefix = {
  var key : raw_input
  proc hash = FixedBackend.hash
  proc derive(tail : raw_input) : digest = {
    var y; y <@ FixedBackend.hash(key ++ tail); return y;
  }
}.











require C10FixedBackend.
lemma checked :
  equiv[FixedBackend.hash ~ C10FixedBackend.FixedBackend.hash :
    ={x} /\ FixedBackend.fn{1} = C10FixedBackend.FixedBackend.fn{2} /\ FixedBackend.history{1} = C10FixedBackend.FixedBackend.history{2} /\ FixedBackend.calls{1} = C10FixedBackend.FixedBackend.calls{2} ==> ={res} /\ FixedBackend.fn{1} = C10FixedBackend.FixedBackend.fn{2} /\ FixedBackend.history{1} = C10FixedBackend.FixedBackend.history{2} /\ FixedBackend.calls{1} = C10FixedBackend.FixedBackend.calls{2}].
proof. proc; sp 1 1; if; auto => />; try ring. qed.

lemma backend_history_nil f h : backend_history f h [] = h.
proof. by rewrite /backend_history. qed.
lemma backend_history_rcons f h xs x :
  backend_history f h (rcons xs x) = remember (backend_history f h xs) x (f x).
proof. by rewrite /backend_history foldl_rcons. qed.
lemma remember_consistent f h x : backend_consistent h f =>
  backend_consistent (remember h x (f x)) f.
proof. rewrite /remember /backend_consistent; smt(get_setE). qed.
lemma remember_preserves h x y z : z \in h => (remember h x y).[z] = h.[z].
proof. rewrite /remember; smt(get_setE). qed.
lemma backend_empty_consistent f : backend_consistent empty f.
proof. rewrite /backend_consistent; smt(emptyE). qed.
lemma backend_history_preserves f h xs z : z \in h =>
  (backend_history f h xs).[z] = h.[z].
proof.
  elim xs h => [h|x xs ih h]; first by rewrite backend_history_nil.
  move=> hz.
  have hr := remember_preserves h x (f x) z hz.
  have hm : z \in remember h x (f x) by smt(domE).
  have he := ih (remember h x (f x)) hm.
  by move: he; rewrite /backend_history /= hr.
qed.
lemma fixed_init f0 :
  hoare[FixedBackend.init : f = f0 ==>
    FixedBackend.fn = f0 /\ FixedBackend.history = empty /\
    backend_consistent FixedBackend.history f0 /\ FixedBackend.calls = 0].
proof. proc; auto; rewrite /backend_consistent; smt(emptyE). qed.
lemma fixed_hash f h x0 c :
  hoare[FixedBackend.hash :
    FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ x = x0 /\ FixedBackend.calls = c ==>
    res = f x0 /\ FixedBackend.fn = f /\
    FixedBackend.history = remember h x0 (f x0) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c + 1].
proof.
  proc; sp 1; if; auto => />;
    rewrite /remember /backend_consistent;
    smt(get_setE get_set_sameE domE).
qed.
lemma fixed_hash_ll : islossless FixedBackend.hash.
proof. proc; auto. qed.
lemma fixed_derive f h tail0 c key0 :
  hoare[FixedPrefix.derive :
    FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ tail = tail0 /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = f (key0 ++ tail0) /\ FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = remember h (key0 ++ tail0) (f (key0 ++ tail0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c + 1].
proof. proc; call (fixed_hash f h (key0 ++ tail0) c); auto. qed.
lemma fixed_derive_ll : islossless FixedPrefix.derive.
proof. proc; call fixed_hash_ll; auto. qed.
