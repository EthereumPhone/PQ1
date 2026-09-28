require import AllCore List StdBigop.
require import VecDP CountDS.

op fs205 : int list = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0].
op fu43  : int list = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0].

(* The 43-step evaluation.  RHS is |C_T| for (len=43, base=8, target=205). *)
lemma c10_kernel : nth 0 (runs 8 fu43 (vinit fs205)) 0 = 22169393903687611906220091621190388.
proof. by []. qed.

(* Sizes, so downstream files never re-count the literals by hand. *)
lemma size_fs205 : size fs205 = 205. proof. by []. qed.
lemma size_fu43  : size fu43  = 43.  proof. by []. qed.

(* ---------------------------------------------------------------------- *)
(*  T3.  Compose the CountDS.ec bridge with the reduction above.           *)
(*                                                                         *)
(*  PERFORMANCE NOTE, paid for the hard way: any tactic that invokes        *)
(*  `trivial` (i.e. `by`, `//`, `smt`) on a goal still CONTAINING the term  *)
(*  `runs 8 fu43 (vinit fs205)` re-runs the 41 s reduction, and `apply`     *)
(*  against such a goal did not terminate in a 120 s budget.  The script    *)
(*  below therefore uses only `rewrite`; the single `by` at the end sees    *)
(*  the already-rewritten goal `N = N`.                                     *)
(* ---------------------------------------------------------------------- *)
lemma c10_surface_count : count_ds 43 8 205 = 22169393903687611906220091621190388.
proof.
have ge0_8 : 0 <= 8.
+ by [].
by rewrite -size_fu43 -size_fs205 (count_ds_kernel 8 fu43 fs205 ge0_8) c10_kernel.
qed.
