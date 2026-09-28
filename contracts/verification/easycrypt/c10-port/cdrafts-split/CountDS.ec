(* ==========================================================================
   CountDS -- machine-checked digit-sum counting.

   WHAT THIS FILE IS.  `count_ds n b s` is the natural recursion counting
   length-`n` words over the digit alphabet {0,...,b-1} whose digits sum to
   `s`.  Three things are proved here:

     T1  the recursion and its shape lemmas          (count_ds0 / count_dsS)
     T2  CORRECTNESS: `count_ds n b s` is the number of DISTINCT digit
         vectors of length n over [0,b) with digit sum s
                                        (count_ds_counts_digit_vectors)
     T3-bridge  `count_ds` agrees with the reducible vector DP of VecDP.ec
                                        (count_ds_kernel)

   WHAT THIS FILE IS *NOT*.  It says nothing about `emsgWOTS`, `encode_msgWOTS`,
   `digitsum` or `target_sum` from WOTS_TW_ES.ec.  The counted objects here are
   `int list`s, not WOTS codewords.  See README.md in this directory for the
   enumerated list of what would have to be proved to close that gap.
   ========================================================================== *)
require import AllCore List StdBigop.
require import VecDP.
import Bigint.BIA.

(* -------------------------------------------------------------------- *)
(*                     T1 -- the counting recursion                     *)
(* -------------------------------------------------------------------- *)

(* One DP layer: from the counts at length n to the counts at length n+1. *)
op cstep (b : int) (f : int -> int) : int -> int =
  fun s => bigi predT (fun d => f (s - d)) 0 b.

op count_ds (n b s : int) : int =
  iter n (cstep b) (fun t => b2i (t = 0)) s.

lemma count_ds0 (b s : int) : count_ds 0 b s = b2i (s = 0).
proof. by rewrite /count_ds iter0. qed.

lemma count_dsS (n b s : int) : 0 <= n =>
  count_ds (n + 1) b s = bigi predT (fun d => count_ds n b (s - d)) 0 b.
proof. by move=> ge0_n; rewrite /count_ds iterS //= /cstep. qed.

(* Below the target range the count is 0 -- needed so the vector DP may read
   "off the end" of its state and get the mathematically right answer. *)
lemma count_ds_neg (n b : int) : 0 <= n =>
  forall s, s < 0 => count_ds n b s = 0.
proof.
elim: n => [|n ge0_n ih] s hs; first by rewrite count_ds0; smt().
rewrite count_dsS //; apply big1_seq => d [_ /mem_range hd] /=.
by apply ih; smt().
qed.

(* -------------------------------------------------------------------- *)
(*             T2 -- what the recursion actually counts                 *)
(* -------------------------------------------------------------------- *)

op is_digit (b d : int) : bool = 0 <= d < b.

(* The explicit enumeration of every length-n word over [0,b). *)
op wstep (b : int) (ws : int list list) : int list list =
  allpairs (fun (d : int) (l : int list) => d :: l) (range 0 b) ws.

op words (n b : int) : int list list = iter n (wstep b) [[]].

lemma words0 (b : int) : words 0 b = [[]].
proof. by rewrite /words iter0. qed.

lemma wordsS (n b : int) : 0 <= n =>
  words (n + 1) b =
    allpairs (fun (d : int) (l : int list) => d :: l) (range 0 b) (words n b).
proof. by move=> ge0_n; rewrite /words iterS // /wstep. qed.

lemma sumz_cons (d : int) (l : int list) : sumz (d :: l) = d + sumz l.
proof. by rewrite /sumz. qed.

(* `words n b` enumerates EXACTLY the length-n digit vectors. *)
lemma mem_words (n b : int) : 0 <= n =>
  forall l, (l \in words n b) <=> (size l = n /\ all (is_digit b) l).
proof.
elim: n => [|n ge0_n ih] l.
+ by rewrite words0 /=; smt(size_eq0).
rewrite wordsS //; split.
+ move/allpairsP => [] [d w] /= [hd] [hw] ->.
  move: hd; rewrite mem_range => hd.
  by move: (ih w); rewrite hw /= /is_digit => -[-> ->] /=; smt().
move=> [hsz hall]; case: l hsz hall => [|d w] /=; first by smt().
move=> hsz [hd hall]; apply/allpairsP; exists (d, w) => /=.
rewrite mem_range; split; first by move: hd; rewrite /is_digit.
by rewrite (ih w) /=; smt().
qed.

lemma uniq_words (n b : int) : 0 <= n => uniq (words n b).
proof.
elim: n => [|n ge0_n ih]; first by rewrite words0.
rewrite wordsS //; apply allpairs_uniq; [exact range_uniq | exact ih |].
by move=> x1 x2 y1 y2 _ _ _ _ /=; smt().
qed.

(* The counting step transported onto the enumeration. *)
lemma count_allpairs_cons (p : int list -> bool) (R : int list)
                          (ws : int list list) :
    count p (allpairs (fun (d : int) (l : int list) => d :: l) R ws)
  = big predT (fun d => count (fun l => p (d :: l)) ws) R.
proof.
elim: R => [|x R ih]; first by rewrite allpairs0l big_nil.
by rewrite allpairs_consl count_cat count_map big_cons /predT /(\o) /= ih.
qed.

(* T2, the real content: the recursion equals the enumeration count. *)
lemma count_ds_correct (n b : int) : 0 <= n =>
  forall s, count_ds n b s = count (fun l => sumz l = s) (words n b).
proof.
elim: n => [|n ge0_n ih] s.
+ by rewrite words0 count_ds0 /sumz /=; smt().
rewrite count_dsS // wordsS // count_allpairs_cons.
apply eq_bigr => d _ /=; rewrite ih.
by apply eq_count => l /=; rewrite sumz_cons; smt().
qed.

(* T2, stated the way it should be read.  `count_ds n b s` is the SIZE of a
   DUPLICATE-FREE list whose members are EXACTLY the length-n vectors over the
   digit alphabet [0,b) whose digits sum to s. *)
lemma count_ds_counts_digit_vectors (n b s : int) : 0 <= n =>
     count_ds n b s = size (filter (fun l => sumz l = s) (words n b))
  /\ uniq (filter (fun l => sumz l = s) (words n b))
  /\ (forall l, (l \in filter (fun l => sumz l = s) (words n b))
                <=> (size l = n /\ all (is_digit b) l /\ sumz l = s)).
proof.
move=> ge0_n; split; first by rewrite size_filter count_ds_correct.
split; first by apply filter_uniq; apply uniq_words.
by move=> l; rewrite mem_filter /= (mem_words n b) //; smt().
qed.

(* -------------------------------------------------------------------- *)
(*        T3-bridge -- count_ds  <->  the reducible vector DP           *)
(* -------------------------------------------------------------------- *)

(* `v` represents the length-n counting layer for targets S, S-1, ..., 0:
   position i of v carries the count for target sum (S - i).  Positions past
   the end read as 0, which matches count_ds at negative targets. *)
op vrep (n b S : int) (v : int list) : bool =
  size v = S + 1 /\ forall i, 0 <= i => nth 0 v i = count_ds n b (S - i).

lemma size_vstep (b : int) (v : int list) : size (vstep b v) = size v.
proof. by elim: v => [|x v ih] //=; rewrite ih. qed.

lemma size_vinit (fs : int list) : size (vinit fs) = size fs + 1.
proof. by elim: fs => [|f fs ih] //=; rewrite ih; smt(). qed.

lemma nth_vinit (fs : int list) : forall i, 0 <= i =>
  nth 0 (vinit fs) i = b2i (i = size fs).
proof.
elim: fs => [|f fs ih] i ge0_i /=; first by smt().
case: (i = 0) => [->|ne0] /=; first by smt(size_ge0).
by rewrite ih 1:/#; smt().
qed.

lemma take_consS (n : int) (x : 'a) (s : 'a list) : 0 <= n =>
  take (n + 1) (x :: s) = x :: take n s.
proof. by move=> ge0_n /=; smt(). qed.

lemma nth_vstep (b : int) (v : int list) : forall i, 0 <= i =>
  nth 0 (vstep b v) i = sumz (take b (drop i v)).
proof.
elim: v => [|x v ih] i ge0_i /=; first by rewrite /sumz.
case: (i = 0) => [->|ne0] /=; first by [].
have -> /= : (i <= 0) = false by smt().
by rewrite ih /#.
qed.

lemma sumz_take_drop (v : int list) (b : int) : 0 <= b =>
  forall i, 0 <= i =>
    sumz (take b (drop i v)) = bigi predT (fun d => nth 0 v (i + d)) 0 b.
proof.
elim: b => [|b ge0_b ih] i ge0_i; first by rewrite take0 /sumz /= big_geq.
case: (i < size v) => [hi|hi].
+ rewrite big_int_recl //= (drop_nth 0 i v) 1:/# take_consS // sumz_cons ih 1:/#.
  by congr; apply eq_bigr => d _ /=; smt().
rewrite drop_oversize 1:/# /= /sumz /= eq_sym.
by apply big1_seq => d [_ /mem_range hd] /=; rewrite nth_default; smt(size_ge0).
qed.

lemma vstep_rep (n b S : int) (v : int list) : 0 <= n => 0 <= b =>
  vrep n b S v => vrep (n + 1) b S (vstep b v).
proof.
move=> ge0_n ge0_b [hsz hnth]; split; first by rewrite size_vstep.
move=> i ge0_i; rewrite nth_vstep // sumz_take_drop // count_dsS //.
by apply eq_big_int => d [ge0_d _] /=; rewrite hnth 1:/#; smt().
qed.

lemma vinit_rep (b S : int) (fs : int list) : size fs = S =>
  vrep 0 b S (vinit fs).
proof.
move=> hsz; split; first by rewrite size_vinit hsz.
by move=> i ge0_i; rewrite nth_vinit // count_ds0 hsz; smt().
qed.

lemma runs_rep (b S : int) (fu : int list) : 0 <= b =>
  forall n v, 0 <= n => vrep n b S v => vrep (n + size fu) b S (runs b fu v).
proof.
move=> ge0_b; elim: fu => [|f fu ih] n v ge0_n hrep /=; first by smt().
have := ih (n + 1) (vstep b v) _ _; 1,2: smt(vstep_rep).
by move=> h; have -> : n + (1 + size fu) = n + 1 + size fu by ring.
qed.

(* THE BRIDGE.  Reading position 0 of the vector DP after `size fu` steps,
   starting from the initial layer of width `size fs + 1`, is exactly
   `count_ds (size fu) b (size fs)`. *)
lemma count_ds_kernel (b : int) (fu fs : int list) : 0 <= b =>
  count_ds (size fu) b (size fs) = nth 0 (runs b fu (vinit fs)) 0.
proof.
move=> ge0_b.
have := runs_rep b (size fs) fu ge0_b 0 (vinit fs) _ _; 1: done.
+ by apply vinit_rep.
by move=> [_ h]; rewrite (h 0) //=.
qed.
