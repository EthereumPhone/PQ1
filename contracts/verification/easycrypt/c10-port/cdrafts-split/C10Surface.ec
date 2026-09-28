(* ==========================================================================
   C10Surface -- T4, the two security-relevant corollaries of T3.

   T3 (`c10_surface_count`) lives in C10SurfaceKernel.ec, where the 43-step
   reduction is paid for exactly once.  This file must never mention `runs`
   or `vinit`: any `trivial`-invoking tactic that sees those terms re-runs the
   41 s reduction.

   SCOPE.  Theorems about `count_ds`, i.e. about DIGIT VECTORS (`int list`s).
   NOT yet theorems about WOTS codewords -- see README.md.
   ========================================================================== *)
require import AllCore List IntDiv Ring StdOrder StdBigop.
require import CountDS C10SurfaceKernel.

(* -------------------------------------------------------------------- *)
(*        integer powers, by the same reducible-structural trick         *)
(* -------------------------------------------------------------------- *)

(* `^` on int is NOT reducible, and smt cannot evaluate 2^114 (measured:
   27 s, then "cannot prove goal (strict)").  A structural power IS. *)
op powl (x : int) (fu : int list) : int =
  with fu = []      => 1
  with fu = _ :: f' => x * powl x f'.

lemma powlE (x : int) (fu : int list) : powl x fu = x ^ (size fu).
proof.
elim: fu => [|f fu ih]; first by rewrite /= expr0.
have -> : size (f :: fu) = size fu + 1 by smt().
by rewrite exprS 1:size_ge0 /= ih.
qed.

op fu14  : int list = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0].
op fu15  : int list = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0].
op fu114 : int list = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0].
op fu115 : int list = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0].

lemma size_fu14  : size fu14  = 14.  proof. by []. qed.
lemma size_fu15  : size fu15  = 15.  proof. by []. qed.
lemma size_fu114 : size fu114 = 114. proof. by []. qed.
lemma size_fu115 : size fu115 = 115. proof. by []. qed.

lemma pow2_14  : 2 ^ 14  = 16384.
proof. by rewrite -size_fu14 -powlE. qed.

lemma pow2_15  : 2 ^ 15  = 32768.
proof. by rewrite -size_fu15 -powlE. qed.

lemma pow2_114 : 2 ^ 114 = 20769187434139310514121985316880384.
proof. by rewrite -size_fu114 -powlE. qed.

lemma pow2_115 : 2 ^ 115 = 41538374868278621028243970633760768.
proof. by rewrite -size_fu115 -powlE. qed.

lemma pow8_43  : 8 ^ 43  = 680564733841876926926749214863536422912.
proof. by rewrite -size_fu43 -powlE. qed.

(* -------------------------------------------------------------------- *)
(*                                 T4                                    *)
(* -------------------------------------------------------------------- *)

(* log2 |C_T| = 114.0941, so the value is strictly between 2^114 and 2^115. *)
lemma c10_surface_bits : 2 ^ 114 < count_ds 43 8 205 < 2 ^ 115.
proof. by rewrite c10_surface_count pow2_114 pow2_115. qed.

(* The surface fraction p = |C_T| / 8^43 satisfies 2^-15 < p < 2^-14
   (exact value 2^-14.9059).  Stated as integer inequalities: no reals. *)
lemma c10_surface_fraction :
     8 ^ 43 < count_ds 43 8 205 * 2 ^ 15
  /\ count_ds 43 8 205 * 2 ^ 14 < 8 ^ 43.
proof. by rewrite c10_surface_count pow2_14 pow2_15 pow8_43. qed.

(* -------------------------------------------------------------------- *)
(*        T2 + T3 composed -- the headline, with no `count_ds` in it     *)
(* -------------------------------------------------------------------- *)

(* There EXISTS a duplicate-free list whose members are EXACTLY the length-43
   vectors over the digit alphabet [0,8) whose digits sum to 205, and its size
   is 22169393903687611906220091621190388.  This is the sentence the FINDING
   states in prose; it is now a theorem about `int list`s.  It is NOT yet a
   theorem about `emsgWOTS` -- see README.md for the enumerated gap. *)
lemma c10_surface_is_a_cardinality :
  exists (W : int list list),
       size W = 22169393903687611906220091621190388
    /\ uniq W
    /\ (forall l, (l \in W)
                  <=> (size l = 43 /\ all (is_digit 8) l /\ sumz l = 205)).
proof.
have ge0_43 : 0 <= 43.
+ by [].
have [h1 [h2 h3]] := count_ds_counts_digit_vectors 43 8 205 ge0_43.
exists (filter (fun (l : int list) => sumz l = 205) (words 43 8)).
split; first by rewrite -h1 c10_surface_count.
by split; [exact h2 | exact h3].
qed.
