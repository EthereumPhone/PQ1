(* ------------------------------------------------------------------------ *)
(*  VecDP -- a REDUCIBLE vector dynamic program for digit-sum counting.      *)
(*                                                                          *)
(*  Everything here is STRUCTURAL recursion on lists, deliberately, because  *)
(*  EasyCrypt's `iota_` (hence `range`/`mkseq`) and `iteri` (hence `iter`,   *)
(*  `nseq`) are AXIOMATISED, not defined -- so `simplify` cannot reduce      *)
(*  them.  Structural list recursion + integer literals DO reduce, which is  *)
(*  what makes the 43-step evaluation in C10SurfaceKernel.ec possible.       *)
(*                                                                          *)
(*  Indexing convention: a state `v` of length S+1 carries at position `i`   *)
(*  the count for target sum (S - i).  With that orientation the DP step     *)
(*      new[i] = v[i] + v[i+1] + ... + v[i+b-1]                             *)
(*  is a sliding window that runs FORWARD along the list, i.e. a plain       *)
(*  structural recursion with no accumulator.                                *)
(* ------------------------------------------------------------------------ *)
require import AllCore List.

op vstep (b : int) (v : int list) : int list =
  with v = []      => []
  with v = x :: v' => sumz (take b (x :: v')) :: vstep b v'.

(* `fuel` is used only for its LENGTH; its contents are irrelevant.  A list is
   used rather than an int because structural recursion is what reduces. *)
op runs (b : int) (fuel : int list) (v : int list) : int list =
  with fuel = []      => v
  with fuel = _ :: f' => runs b f' (vstep b v).

(* `vinit fs` = [0; ...; 0; 1] with (size fs) zeros: the n = 0 state, i.e.
   count 1 at target sum 0 (position size fs) and 0 everywhere else. *)
op vinit (fs : int list) : int list =
  with fs = []      => [1]
  with fs = _ :: f' => 0 :: vinit f'.
