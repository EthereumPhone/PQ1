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
    calls <- calls + 1;
    if (x \notin history) { history.[x] <- fn x; }
    return [];
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
