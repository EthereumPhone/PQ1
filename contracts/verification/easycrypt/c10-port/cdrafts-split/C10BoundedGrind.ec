(* The firmware's finite signing prefix, over the actual WOTS_C_Real
   predicate/counter. -1 models exhaustion (Rust panics on that path).
   This is a manual control-flow model, not an extracted Rust program.
   The existing total signing game is unchanged. *)
require import AllCore List.
require import SPHINCS_PLUS WOTS_C_Real C10Counter.
import FSSLXMTWES FSSLXMTWES.WTWES.

op of_int (i : int) : cntr = oget (U32.insub i).
op hit (ps : pseed) (ad : adrs) (m : dgstblock) (i : int) =
  predC (ThC ps ad m (of_int i)).

module Search = {
  proc run(ps : pseed, ad : adrs, m : dgstblock) : int = {
    var i, r : int;
    var found : bool;
    i <- 0;
    r <- -1;
    found <- false;
    while (!found /\ i < signing_budget) {
      if (hit ps ad m i) {
        r <- i;
        found <- true;
      }
      i <- i + 1;
    }
    return r;
  }
}.

lemma search_ll : islossless Search.run.
proof. by islossless; while true (signing_budget - i); auto; smt(). qed.

lemma search_spec (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock) :
  hoare[Search.run : ps = ps0 /\ ad = ad0 /\ m = m0 ==>
    (res = -1 <=> forall j, 0 <= j < signing_budget => !hit ps0 ad0 m0 j) /\
    (res <> -1 => 0 <= res < signing_budget /\ hit ps0 ad0 m0 res /\
                 forall j, 0 <= j < res => !hit ps0 ad0 m0 j)].
proof.
  proc.
  while (ps = ps0 /\ ad = ad0 /\ m = m0 /\ 0 <= i <= signing_budget /\
    (!found => r = -1 /\ forall j, 0 <= j < i => !hit ps0 ad0 m0 j) /\
    (found => 0 <= r < signing_budget /\ hit ps0 ad0 m0 r /\
              forall j, 0 <= j < r => !hit ps0 ad0 m0 j)).
  + auto => /> *; smt().
  auto => />; rewrite /signing_budget; smt().
qed.

lemma of_int_value (i : int) :
  0 <= i < 4294967296 => U32.val (of_int i) = i.
proof. move=> hi; move: (U32.insubT i hi); rewrite /of_int; by case (U32.insub i). qed.

(* This bridge is to the actual grindC called by WOTS_C_ES.sign. A hit in
   the signing prefix is also the first hit in the full ascending u32 domain. *)
lemma first_hit_agrees (ps : pseed) (ad : adrs) (m : dgstblock) (r : int) :
  0 <= r < signing_budget => hit ps ad m r =>
  (forall j, 0 <= j < r => !hit ps ad m j) =>
  grindC ps ad m = of_int r.
proof.
  move=> hr hh hbefore.
  have hr32 : r < 4294967296 by move: hr; rewrite /signing_budget; smt().
  have hnil : filter (fun j => hit ps ad m j) (range 0 r) = [].
  + apply eq_in_filter_pred0; by move=> j; rewrite mem_range; apply hbefore.
  rewrite /grindC /STCRC_WC.G.grind /STCRC_WC.G.good_ctrs
    /STCRC_WC.G.CntrFT.enum /C10Counter.enum filter_map.
  change (head witness (map of_int (filter (hit ps ad m) (range 0 4294967296))) = of_int r).
  by rewrite (range_cat r) 1:/# 1:/# filter_cat hnil /=
    range_ltn 1:hr32 /= hh.
qed.

lemma search_success_refines_grind (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock) :
  hoare[Search.run : ps = ps0 /\ ad = ad0 /\ m = m0 ==>
    res <> -1 => grindC ps0 ad0 m0 = of_int res].
proof.
  conseq (search_spec ps0 ad0 m0); smt(first_hit_agrees).
qed.
