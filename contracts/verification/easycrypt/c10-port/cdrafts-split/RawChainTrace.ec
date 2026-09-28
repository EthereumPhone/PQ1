(* Correspondence of the actual raw WOTS loop to its retained chain entries. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import LinearChain LinearOracle.

op chain_input (seed : raw_input) (layer tree kp index step : int) (value : raw_input) =
  seed ++ address layer tree 0 kp index step 0 ++ pad value.

lemma raw_chain_recorded seed0 layer0 tree0 kp0 index0 initial start0 stop0 :
  hoare [RawWots(PreparationView(Independent)).chain :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ index = index0 /\
    current = initial /\ start = start0 /\ stop = stop0 /\ start0 <= stop0 ==>
    linear_recorded Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 stop0) /\
    res = linear_value Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 stop0)].
proof.
  proc; while (seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ index = index0 /\
    stop = stop0 /\ start0 <= j <= stop0 /\
    linear_recorded Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 j) /\
    linear_value Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 j) = current).
  + exists* j,current; elim* => j0 current0.
    wp; call (hash_preserves_linear (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 j0) current0
      (chain_input seed0 layer0 tree0 kp0 index0 j0 current0)).
    auto; move=> &hr [[hj hc] [hinv hguard]].
    move: hinv => [hs [hl [ht [hk [hi [hstop [hrange [hrecord hvalue]]]]]]]].
    split.
    + split; first smt().
      split; first smt().
      by rewrite /chain_input; smt().
    move=> _ d h [hrec [hval hentry]].
    have hstep := linear_recorded_step h
      (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 j0) j0 d current0 hrec hval hentry.
    have hrange' : range start0 (j{hr} + 1) = rcons (range start0 j0) j0
      by smt(rangeSr).
    rewrite hrange'; smt().
  auto; move=> &hr hp; split.
  + have hstart : start{hr} = start0 by smt().
    rewrite hstart range_geq 1:// /linear_value /=; smt().
  smt().
qed.
