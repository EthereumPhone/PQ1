(* MUST-FAIL CONTROL for P2.  If a bare `smt()` closes THIS, P2 proved nothing about
   reachability -- it would just mean smt closes anything in this shape.
   This drops `m <> m'`.  The tree's own refutation (project note, 2026-08-12) is that
   under `m = m'` the statement is FALSE: is_chwcoll and is_chwpre share the conjunct
   `BaseW.val em'.[i] < BaseW.val em.[i]`, which under `em = em'` is `x < x` -- false at
   every index -- so `!has_chwcoll` HOLDS while `has_chwpre` FAILS. *)
require import AllCore.
require import SPHINCS_PLUS.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.

lemma P2NEG_must_fail (ps : pseed) (ad : adrs) (m m' : msgWOTS) (sig sig' : sigWOTS) :
     P m
  => P m'
  => !has_chwcoll ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'
  => has_chwpre ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'.
proof. smt(). qed.
