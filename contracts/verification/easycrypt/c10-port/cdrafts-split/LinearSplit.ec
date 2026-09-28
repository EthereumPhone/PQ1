(* Splitting a recorded chain preserves its value and both retained segments. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen LinearChain.

lemma linear_range_split h f value start middle stop :
  start <= middle => middle <= stop =>
  linear_recorded h f value (range start stop) =>
  linear_recorded h f value (range start middle) /\
  linear_recorded h f (linear_value h f value (range start middle)) (range middle stop) /\
  linear_value h f value (range start stop) =
    linear_value h f (linear_value h f value (range start middle)) (range middle stop).
proof.
  move=> hs hm; rewrite (range_cat middle start stop hs hm).
  smt(linear_recorded_cat linear_value_cat).
qed.
