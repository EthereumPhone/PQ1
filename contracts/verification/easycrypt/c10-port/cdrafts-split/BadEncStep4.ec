(* PROMOTED 2026-09-14 into the certified closure from
   experiments/wots-badenc/red/BadEncStep4.ec (proved there 2026-08-14).
   CODE IS IDENTICAL to that copy once comments are stripped -- asserted by
   scratch/promote_tcoll_chain.py, not claimed.  COMMENT EDITS ONLY: the
   experiment-relative paths (../base, ../cd, ../tcoll) point at the live trees;
   every file:line citation was re-checked against them and the moved ones updated;
   expired claims are corrected at the sentence and marked [CORRECTED 2026-09-14].
   The experiment copy is kept unedited as the historical record. *)
(* ==========================================================================
   BadEncStep4.ec  --  STEP 4 of the BadEnc -> +C reduction: the PROBABILITY
   INEQUALITY, CLOSED.

       Pr[Game4_WOTSTWES_BadEnc(R_int_WOTSTW(A)).main : res /\ BadEncFlag.badenc]
         <= Pr[T_COLL_RES_ENUM(R_TCOLL(A), O_TCollEnum_Default,
                               FC.O_THFC_Default).main : res]

   Steps 1-3 are `BadEncSplit.ec` (the B1/B2 split) and `BadEncToTColl.ec`
   (`R_TCOLL` + the event-level lemma).  This file supplies the game hop those
   two deliberately did not.

   ###################  WHAT THIS DOES *NOT* DO  ############################
   IT MOVES THE CHARGE.  IT DOES NOT BOUND IT.  Nothing here (or anywhere in
   the tree) bounds `Pr[T_COLL_RES_ENUM(...)]`; `cdrafts-split/TCollResEnum.ec`
   section 6 shows the win is reachable in principle and says nothing about how
   much it costs.  The fork's WOTS-TW bound now has a summand that is a +C-layer
   target-collision term instead of a WOTS-TW-layer term that
   `cdrafts-split/BadEncCountermodel.ec` PROVED equals 1 for an explicit adversary.
   That is the whole content: the term stops being provably unbounded-at-1 and
   becomes an assumption at a layer where the message is a keyed digest.  It is
   still an unbounded assumption.

   `T_COLL_RES_ENUM` also has NO disjointness conjunct (`cdrafts-split/
   TCollResEnum.ec`, FAITHFULNESS NOTES), so its win set is LARGER than the
   S-TCR(+C) template's and the assumption is correspondingly STRONGER.
   ##########################################################################

   THE PREMISE, AND WHY IT IS NOT A FUDGE
   --------------------------------------
   `c <= p_tgts` is required and is not derivable in scope: the left game bounds
   the QUERY count by `c` (`0 <= nrqs <= c`) while `T_COLL_RES_ENUM` bounds the
   TARGET count by `p_tgts` (`nrts <= p_tgts`).  It is used in EXACTLY ONE place
   (`s4_transfer`, the `size ts <= p_tgts` conjunct) and it is minimal: both
   sides append exactly one entry per A signing query, so `size ts = size qs =
   nrqs`.  It is also the development's OWN premise in this exact role --
   `cdrafts-split/WOTS_C_Interactive.ec:1350` states it as "one target per query, S-TCR
   cap >= query cap" and `interactive_hop1` (:1374, :1590, :2304, :2979) carries
   it verbatim.  Nothing new is assumed here.

   THE SIMULATION IS PERFECT -- NO FINDING AGAINST `R_TCOLL`
   --------------------------------------------------------
   The task's stop condition was: if `R_TCOLL(A)` does not present A with
   EXACTLY the view `R_int_WOTSTW(A)` presents inside Game 4, report where and
   stop.  It does.  `query_eq_badenc` proves `={res}` and preserves `={glob A}`,
   which IS that statement, and every ingredient matches:

     * the counter        -- both sides `grindC ps ad m` (left: the enumeration
                             loop; right: the target oracle's op);
     * the encoding       -- both `encode_msgWOTS (ThC ps ad m (grindC ps ad m))`;
     * the secret elements-- both sample `ddgstblock` once per chain, in order;
     * the signature      -- left `cf ps (set_chidx ad i) (em_ele-1) 1`, right one
                             `OC` step: equal by `ch1`;
     * the public key     -- left `cf .. em_ele (w-1-em_ele)`, right the `OC`
                             walk `j = em_ele .. w-2`: equal by `chS`.

   The ONE genuine divergence is the `FC.O_THFC_Default.tws` transcript, and it
   is provably invisible rather than argued away: `get_tweaks` is NOT in
   `Adv_MEUFGCMA_WOTSC.choose`'s allowed set (`{ O.query, OC.query }`,
   `cdrafts-split/WOTS_C_Scheme.ec:142`) and `OC.query` answers `fc (size x) pp tw x`
   with no read of `tws` (`base-c10-split/TweakableHashFunctions.eca:577-596`).  So
   `tws` is deliberately absent from every invariant below.

   AXIOM / ADMIT LEDGER.  0 admits, 0 axioms, 0 `declare axiom`.  Check with
     perl -0777 -pe 's/\(\*.*?\*\)//gs' BadEncStep4.ec \
       | grep -cE 'admit|^[[:space:]]*axiom |declare axiom'

   BUILD.  compiled as a target by `cert_gate_split.sh` (closure member since
   2026-09-14; pre-promotion receipt `experiments/wots-badenc/red/BadEncStep4.out`).
   `BadEncSplit` and `BadEncToTColl` are re-verified as TARGETS in the same run
   (a `require` does NOT re-check a dependency -- see the standing note in
   `experiments/wots-badenc/RESULT.md`).

   THE EXPORTED STATEMENT, READ OFF `print` RATHER THAN INFERRED FROM RC=0
   ----------------------------------------------------------------------
   `badenc_le_tcoll` lives inside `section Step4`; section closing generalises
   over `A` and rewrites the statement, so RC=0 says the script closed, not what
   was exported.  `experiments/wots-badenc/red/printstmt.sh` (receipt `printstmt.out`
   there; RE-PRINTED against the live trees 2026-09-14 before promotion --
   same restriction set, same premise, same two games) prints it:

     lemma badenc_le_tcoll:
       forall (A <: Adv_MEUFGCMA_WOTSC{-FC.O_THFC_Default,
                 -O_MEUFGCMA_WOTSTWESNPRF, -O_MEUFGCMA_WOTSC_Default,
                 -O_TCollEnum_Default, -R_int_WOTSTW, -R_TCOLL}) &m,
         WOTS_C_Real.c <= WOTS_C_Real.p_tgts =>
         Pr[Game4_WOTSTWES_BadEnc(R_int_WOTSTW(A)).main() @ &m
              : res /\ BadEncFlag.badenc]
         <= Pr[T_COLL_RES_ENUM(R_TCOLL(A), O_TCollEnum_Default,
                               FC.O_THFC_Default).main() @ &m : res].

   The premise survived, the restriction set is the six declared and no more,
   and both games are the intended ones.  `c` here is not an abstract constant:
   `base-c10-split/FL_SL_XMSS_MT_ES.ec:554` clones WOTS-TW with
   `op c <- bigi predT (fun d' => nr_nodes_ht d' 0) 0 d`, which is exactly the
   quantity `Game4_WOTSTWES_BadEnc`'s own `0 <= nrqs <= c` conjunct bounds.

   NEGATIVE CONTROLS -- SEVEN, ALL MUST FAIL, ALL DO.  Regenerate with
   `scratch/mkctl_bes4.sh` (S4CtlA..G =
   `scratch/bes4_ctl{A..G}.ec`); the gate runs them from
   `cert-controls-split.tsv` and grades the declared reason.  A--F each delete exactly ONE fact and leave every
   intro arity unchanged; G is a different kind, flagged below.  NONE produces a
   `.eco`.

     S4CtlA  `s4_transfer` without `c <= p_tgts`
               RC=1  `cannot prove goal (strict)` at the SECOND `split` of
                     `s4_transfer` -- i.e. precisely the `size ts <= p_tgts`
                     conjunct, the premise's only consumer.
     S4CtlB  `s4_transfer` without `s4_ts_enc ts`
               RC=1  `true ... but is expected to prove: s4_ts_enc ts` at
                     `s4_ts_enc_nth` -- the stored-codeword fact, which is what
                     turns the left game's `badenc` into the right game's
                     `e = e'`.
     S4CtlC  `s4_transfer` without `s4_wads_ts wads ts`
               RC=1  `true ... but is expected to prove: s4_wads_ts wads ts` at
                     `s4_wads_ts_nth` -- the address log/target log parallelism,
                     i.e. THE fact that puts both `ThC` images at a COMMON
                     tweak.  Without it the two digests sit at unrelated
                     addresses and the win is not `EncNonInjOnThCSurface`.
     S4CtlD  the grind while-invariant without
             `!found => head (filter ...) = grindC`
               RC=1  `cannot prove goal (strict)` in `query_eq_badenc`'s grind
                     body -- the `found => c = grindC` conjunct is exactly what
                     that fact re-establishes.  This is the control that shows
                     obstacle (a) was SOLVED and not sidestepped.
     S4CtlE  the `seq 20 0` coupling assertion without `em{1} = em{2}`
               RC=1  `cannot prove goal (strict)` at `query_eq_badenc`'s closing
                     `skip` -- the two chain loops cannot be entered, so the
                     simulated signature is no longer the game's signature.
     S4CtlF  `s4_transfer` without `s4_qs_ts qs ts`
               RC=1  `true ... but is expected to prove: s4_qs_ts qs ts` at
                     `s4_qs_ts_size` -- the log/log message-vs-digest
                     parallelism, which is what transfers `dg <> dg'` and
                     `P dg`.
     S4CtlG  `badenc_le_tcoll` without the `s4_transfer` INSTANCE (the two
             `have := s4_transfer ...` lines deleted; everything else, including
             `hpre`, left in place)
               RC=1  `cannot prove goal (strict)` at the closing `smt()`.

   S4CtlG IS A DIFFERENT KIND OF CONTROL and is labelled so deliberately: it is
   a NECESSITY control on a PROOF STEP, not an intro-arity-preserving deletion
   of information.  It exists because A/B/C/F all fail INSIDE `s4_transfer`, so
   by themselves they only show that lemma needs its premises -- they would say
   nothing about the BOUND if the headline's closing `smt()` could discharge the
   residual from the raw hypotheses anyway.  G shows it cannot, so `s4_transfer`
   is on the path and A/B/C/F do bear on the bound.  Had G compiled, `s4_transfer`
   would have been decoration and this ledger would be worth much less; it does
   not compile.

   NOT CONTROLLED, ON PURPOSE: the `tws` transcript.  It is provably invisible
   (see above), so "deleting" it deletes nothing and the control would compile
   green -- which is why it is named here instead.
   ========================================================================== *)
require import AllCore List Distr.
require import SPHINCS_PLUS.
require WOTS_C_Real.
require import WOTS_C_Scheme.
require WOTS_C_Reduction.
require import TCollResEnum.
require import BadEncSplit.
require import BadEncToTColl.
require import WOTS_C_Interactive.
import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import WOTS_C_Reduction.   (* grindC_filter: the grind's head/filter form *)
import EmsgWOTS.        (* for `em.[i]`; SHADOWS `val`, so every projection
                           below is qualified by its type *)

(* ==========================================================================
   0.  CHAIN ALGEBRA.

   The left-hand oracle applies `cf` in one shot; the right-hand simulation
   walks `OC` one `f`-step at a time.  These two lemmas are the ONLY content of
   that difference -- both are `ch0`/`chS` at the shape the loops leave, stated
   here so the nested `while{2}` body is a single `smt(...)` on a named fact
   rather than raw `chS` juggling inside a `call`.
   ========================================================================== *)

(* zero steps: the chain at its own starting point *)
lemma cf_base (ps : pseed) (ad : adrs) (e : int) (x : dgstblock) :
     valid_wadrs ad
  => cf ps ad e 0 (DigestBlock.val x) = x.
proof.
move=> hva.
rewrite /cf ch0 //.
+ exact DigestBlock.valP.
exact DigestBlock.valKd.
qed.

(* one more step, from the TOP of the chain: exactly `chS` re-associated so the
   loop index `j` (the tweak's hash index) is the visible parameter *)
lemma cf_step (ps : pseed) (ad : adrs) (e j : int) (x : dgstblock) :
     valid_wadrs ad
  => 0 <= e
  => e <= j
  => j < w - 1
  =>   f ps (set_hidx ad j)
         (DigestBlock.val (cf ps ad e (j - e) (DigestBlock.val x)))
     = cf ps ad e (j + 1 - e) (DigestBlock.val x).
proof.
move=> hva ge0_e le_ej lt_jw.
rewrite /cf (chS f ps ad e (j + 1 - e) (DigestBlock.val x)) //.
+ exact DigestBlock.valP.
+ smt().
+ smt().
by congr; congr; smt().
qed.

(* The `f`-vs-`thfc` identification the collection oracle forces: `OC.query`
   returns `fc (size x) pp tw x = thfc (size x) pp tw x`, and on a `dgstblock`
   image that size is `8 * n`, which is `f`'s member index. *)
lemma thfc_is_f (ps : pseed) (ad : adrs) (x : dgstblock) :
  thfc (size (DigestBlock.val x)) ps ad (DigestBlock.val x)
  = f ps ad (DigestBlock.val x).
proof. by rewrite DigestBlock.valP. qed.

(* ==========================================================================
   1.  THE THREE INDEX-PARALLEL INVARIANTS, AS NAMED OPS.

   Each is `rcons`-closed by one `O_wrap.query` call on each side, and each is
   consumed by the final residual as a PROOF TERM (control hygiene: a control
   deleting one fails at the `apply`, not at a `rewrite`).
   ========================================================================== *)

(* the WOTS-TW query log's MESSAGES are the target log's DIGESTS, index-parallel *)
op s4_qs_ts (qs : (adrs * msgWOTS * pkWOTS * sigWOTS) list)
            (ts : tcoll_entry list) : bool =
  map (fun (q : adrs * msgWOTS * pkWOTS * sigWOTS) => q.`2) qs
  = map (fun (t : tcoll_entry) => t.`4) ts.

(* the reduction's address log and the target log's ADDRESSES, index-parallel.
   THIS is what makes the forged digest sit at the SAME tweak on both sides. *)
op s4_wads_ts (wads : wadrs list) (ts : tcoll_entry list) : bool =
  map WAddress.val wads = map (fun (t : tcoll_entry) => t.`1) ts.

(* the target log's stored codeword really is its stored digest's encoding *)
op s4_ts_enc (ts : tcoll_entry list) : bool =
  all (fun (t : tcoll_entry) => t.`5 = encode_msgWOTS t.`4) ts.

lemma s4_qs_ts_size (qs : (adrs * msgWOTS * pkWOTS * sigWOTS) list)
                    (ts : tcoll_entry list) :
  s4_qs_ts qs ts => size qs = size ts.
proof.
rewrite /s4_qs_ts => h.
by rewrite -(size_map (fun (q : adrs * msgWOTS * pkWOTS * sigWOTS) => q.`2)) h size_map.
qed.

lemma s4_qs_ts_nth (qs : (adrs * msgWOTS * pkWOTS * sigWOTS) list)
                   (ts : tcoll_entry list) (i : int) :
     s4_qs_ts qs ts
  => 0 <= i < size qs
  => (nth witness qs i).`2 = (nth witness ts i).`4.
proof.
move=> h hi.
have hsz := s4_qs_ts_size qs ts h.
rewrite -(nth_map witness witness (fun (q : adrs * msgWOTS * pkWOTS * sigWOTS) => q.`2)) 1:/#.
by move: h; rewrite /s4_qs_ts => ->; rewrite (nth_map witness witness) /#.
qed.

lemma s4_wads_ts_nth (wads : wadrs list) (ts : tcoll_entry list) (i : int) :
     s4_wads_ts wads ts
  => 0 <= i < size ts
  => WAddress.val (nth witness wads i) = (nth witness ts i).`1.
proof.
move=> h hi.
have hsz : size wads = size ts.
+ by move: h; rewrite /s4_wads_ts -(size_map WAddress.val) => ->; rewrite size_map.
rewrite -(nth_map witness witness WAddress.val) 1:/#.
by move: h; rewrite /s4_wads_ts => ->; rewrite (nth_map witness witness) /#.
qed.

lemma s4_ts_enc_nth (ts : tcoll_entry list) (i : int) :
     s4_ts_enc ts
  => 0 <= i < size ts
  => (nth witness ts i).`5 = encode_msgWOTS (nth witness ts i).`4.
proof.
move=> h hi; move: h; rewrite /s4_ts_enc allP => h.
by have := h (nth witness ts i) _; [apply mem_nth; smt() | smt()].
qed.

(* -- rcons closure, one named fact per invariant -- *)
lemma s4_qs_ts_rcons (qs : (adrs * msgWOTS * pkWOTS * sigWOTS) list)
                     (ts : tcoll_entry list)
                     (q : adrs * msgWOTS * pkWOTS * sigWOTS) (t : tcoll_entry) :
  s4_qs_ts qs ts => q.`2 = t.`4 => s4_qs_ts (rcons qs q) (rcons ts t).
proof. by rewrite /s4_qs_ts !map_rcons /= => -> ->. qed.

lemma s4_wads_ts_rcons (wads : wadrs list) (ts : tcoll_entry list)
                       (wad : wadrs) (t : tcoll_entry) :
  s4_wads_ts wads ts => WAddress.val wad = t.`1 => s4_wads_ts (rcons wads wad) (rcons ts t).
proof. by rewrite /s4_wads_ts !map_rcons /= => -> ->. qed.

lemma s4_ts_enc_rcons (ts : tcoll_entry list) (t : tcoll_entry) :
  s4_ts_enc ts => t.`5 = encode_msgWOTS t.`4 => s4_ts_enc (rcons ts t).
proof. by rewrite /s4_ts_enc -cats1 all_cat /= => -> ->. qed.

(* ==========================================================================
   2.  THE RESIDUAL, AS ONE PURE LEMMA.

   Left-hand win + BadEnc, plus the three invariants, plus `c <= p_tgts`, give
   the right-hand win EXACTLY.  Stated over the raw values so the game proof
   consumes it by `apply` on a proof term.

   `c <= p_tgts` is used in EXACTLY ONE place -- the `nrts <= p_tgts` conjunct --
   and it is minimal: both sides append exactly one entry per A signing query,
   so `size ts = size qs = nrqs`, and the left game already bounds `nrqs <= c`.
   ========================================================================== *)
lemma s4_transfer (ps : pseed)
      (qs : (adrs * msgWOTS * pkWOTS * sigWOTS) list) (ts : tcoll_entry list)
      (wads : wadrs list) (i : int) (mA : dgstblock) (ctrA : cntr) :
     c <= p_tgts
  => s4_qs_ts qs ts
  => s4_wads_ts wads ts
  => s4_ts_enc ts
  => (   size qs <= c
      /\ 0 <= i < size qs
      /\ ThC ps (WAddress.val (nth witness wads i)) mA ctrA <> (nth witness qs i).`2
      /\ P (nth witness qs i).`2
      /\ P (ThC ps (WAddress.val (nth witness wads i)) mA ctrA)
      /\   encode_msgWOTS (nth witness qs i).`2
         = encode_msgWOTS (ThC ps (WAddress.val (nth witness wads i)) mA ctrA))
  =>    0 <= i < size ts
     /\ size ts <= p_tgts
     /\ (nth witness ts i).`4 <> ThC ps (nth witness ts i).`1 mA ctrA
     /\ P (nth witness ts i).`4
     /\ P (ThC ps (nth witness ts i).`1 mA ctrA)
     /\ (nth witness ts i).`5 = encode_msgWOTS (ThC ps (nth witness ts i).`1 mA ctrA).
proof.
move=> hcp hqt hwt hte [hnq [hi [hfresh [hP [hP' hcol]]]]].
have hsz := s4_qs_ts_size qs ts hqt.
have hdg := s4_qs_ts_nth qs ts i hqt hi.
have had := s4_wads_ts_nth wads ts i hwt _; first smt().
have hen := s4_ts_enc_nth ts i hte _; first smt().
(* Six single `split`s, NOT `do ! split`: the leading `0 <= i < size ts` is
   itself a conjunction, so `do !` would produce seven goals and silently
   mis-align the bullets. *)
rewrite -had -hdg.
split; first smt().
split; first smt().
split; first smt().
split; first smt().
split; first smt().
by rewrite hen -hdg; exact hcol.
qed.


(* -- "one entry pending on the left" forms.  The RIGHT side registers its
      target entry at the START of a query; the LEFT side appends its WOTS-TW
      log entry at the END.  Carrying the parallelism through the middle of the
      query therefore needs the shape with the left list one entry short, which
      these two ops name.  Note `s4_qs_ts` reads only `.`2` of a `qs` entry, so
      the pk/sig components never enter -- which is why `_close` below has no
      side condition. -- *)
op s4_qs_ts_pend (qs : (adrs * msgWOTS * pkWOTS * sigWOTS) list)
                 (dg : msgWOTS) (ts : tcoll_entry list) : bool =
  rcons (map (fun (q : adrs * msgWOTS * pkWOTS * sigWOTS) => q.`2) qs) dg
  = map (fun (t : tcoll_entry) => t.`4) ts.

op s4_wads_ts_pend (wads : wadrs list) (ad : adrs) (ts : tcoll_entry list) : bool =
  rcons (map WAddress.val wads) ad = map (fun (t : tcoll_entry) => t.`1) ts.

(* open: the right side has just appended its target entry *)
lemma s4_qs_ts_open (qs : (adrs * msgWOTS * pkWOTS * sigWOTS) list)
                    (ts : tcoll_entry list) (a : adrs) (mm : dgstblock)
                    (cc : cntr) (dg : msgWOTS) (e : EmsgWOTS.emsgWOTS) :
  s4_qs_ts qs ts => s4_qs_ts_pend qs dg (rcons ts (a, mm, cc, dg, e)).
proof. by rewrite /s4_qs_ts /s4_qs_ts_pend map_rcons /= => ->. qed.

lemma s4_wads_ts_open (wads : wadrs list) (ts : tcoll_entry list) (a : adrs)
                      (mm : dgstblock) (cc : cntr) (dg : msgWOTS)
                      (e : EmsgWOTS.emsgWOTS) :
  s4_wads_ts wads ts => s4_wads_ts_pend wads a (rcons ts (a, mm, cc, dg, e)).
proof. by rewrite /s4_wads_ts /s4_wads_ts_pend map_rcons /= => ->. qed.

lemma s4_ts_enc_rcons_enc (ts : tcoll_entry list) (a : adrs) (mm : dgstblock)
                          (cc : cntr) (dg : msgWOTS) :
  s4_ts_enc ts => s4_ts_enc (rcons ts (a, mm, cc, dg, encode_msgWOTS dg)).
proof. by rewrite /s4_ts_enc -cats1 all_cat /= => ->. qed.

(* close: the left side now appends its own WOTS-TW entry *)
lemma s4_qs_ts_close (qs : (adrs * msgWOTS * pkWOTS * sigWOTS) list)
                     (dg : msgWOTS) (ts : tcoll_entry list)
                     (a : adrs) (p : pkWOTS) (sg : sigWOTS) :
  s4_qs_ts_pend qs dg ts => s4_qs_ts (rcons qs (a, dg, p, sg)) ts.
proof. by rewrite /s4_qs_ts /s4_qs_ts_pend map_rcons /=. qed.

lemma s4_wads_ts_close (wads : wadrs list) (ts : tcoll_entry list) (wad : wadrs) :
  s4_wads_ts_pend wads (WAddress.val wad) ts => s4_wads_ts (rcons wads wad) ts.
proof. by rewrite /s4_wads_ts /s4_wads_ts_pend map_rcons /=. qed.

(* ==========================================================================
   2b. THE CHAIN WALKS, IN THE EXACT SHAPE THE LOOPS LEAVE.

   `OC.query`'s result is `fc (size x) pp tw x = thfc (size x) pp tw x`; on a
   `dgstblock` image that size is `8 * n`, which is `f`'s member index.  These
   three lemmas fold that identification together with `ch0`/`ch1`/`chS` so each
   loop body is a single named fact rather than raw chain juggling inside a
   `call`.
   ========================================================================== *)

(* the signature element, `em_ele <> 0` branch: one `OC` step = `cf .. 1` *)
lemma sig_walk_step (ps : pseed) (ad : adrs) (k e : int) (x : dgstblock) :
     valid_wadrs ad
  => 0 <= k < len
  => 1 <= e < w
  =>   thfc (size (DigestBlock.val x)) ps
            (set_hidx (set_chidx ad k) (e - 1)) (DigestBlock.val x)
     = cf ps (set_chidx ad k) (e - 1) 1 (DigestBlock.val x).
proof.
move=> hva hk he.
have hvc : valid_wadrs (set_chidx ad k)
  by apply validwadrs_setchidx; [exact hva | rewrite /valid_chidx; smt()].
by rewrite thfc_is_f /cf ch1 // 1:DigestBlock.valP 1:/# /#.
qed.

(* the public-key walk, entry: zero steps *)
lemma pk_walk_base (ps : pseed) (ad : adrs) (k e : int) (x : dgstblock) :
     valid_wadrs ad
  => 0 <= k < len
  => cf ps (set_chidx ad k) e 0 (DigestBlock.val x) = x.
proof.
move=> hva hk; apply cf_base.
by apply validwadrs_setchidx; [exact hva | rewrite /valid_chidx; smt()].
qed.

(* the public-key walk, one loop iteration *)
lemma pk_walk_step (ps : pseed) (ad : adrs) (k e j : int) (x : dgstblock) :
     valid_wadrs ad
  => 0 <= k < len
  => 0 <= e
  => e <= j
  => j < w - 1
  =>   thfc (size (DigestBlock.val
                     (cf ps (set_chidx ad k) e (j - e) (DigestBlock.val x))))
            ps (set_hidx (set_chidx ad k) j)
            (DigestBlock.val (cf ps (set_chidx ad k) e (j - e) (DigestBlock.val x)))
     = cf ps (set_chidx ad k) e (j + 1 - e) (DigestBlock.val x).
proof.
move=> hva hk ge0_e le_ej lt_jw.
rewrite thfc_is_f; apply cf_step => //.
by apply validwadrs_setchidx; [exact hva | rewrite /valid_chidx; smt()].
qed.

(* ==========================================================================
   3.  THE PER-QUERY COUPLING -- the heart of the hop.

   `R_int_WOTSTW`'s wrapper (inside Game 4) and `R_TCOLL`'s wrapper answer A's
   WOTS+C signing query with the SAME `(pk, (sig, c))`.  Four differences are
   reconciled here, and NONE of them is visible to A:

     (a) THE GRIND.  Left: a `CntrFT.enum` loop making two `OC` queries per
         candidate.  Right: the op `grindC`, inside the target oracle.  Same
         while-argument as `cdrafts-split/WOTS_C_Interactive.ec`'s `query_eq_tw`, sides
         swapped -- INCLUDING the `!found => head (filter ...) = grindC`
         conjunct, without which the grind-failure exit (`cs = []`, so
         `c = witness`) does not match `grindC`.
     (b) THE CHAIN WALKS.  Left: `cf` applied in one shot.  Right: `OC` walked
         one `f`-step at a time.  Unrolled by section 2b (= `ch0`/`ch1`/`chS`).
     (c) THE OC TRANSCRIPT DIVERGES, deliberately.  `FC.O_THFC_Default.tws` is
         NOT in the invariant.  It cannot matter: `Adv_MEUFGCMA_WOTSC.choose` is
         declared `{ O.query, OC.query }` (`cdrafts-split/WOTS_C_Scheme.ec:142`), so
         `get_tweaks` is NOT in A's allowed set, and `OC.query`'s result is
         `fc (size x) pp tw x` -- a function of `(pp, tw, x)` alone, with no
         read of `tws` (`base-c10-split/TweakableHashFunctions.eca:577-596`).
     (d) THE RECORD ORDER.  The right side registers its target entry FIRST (the
         query is what registers it); the left side appends its WOTS-TW entry
         LAST.  Hence the `_pend` forms above.
   ========================================================================== *)
equiv query_eq_badenc
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_WOTSTW, -R_TCOLL, -O_MEUFGCMA_WOTSC_Default,
                           -O_MEUFGCMA_WOTSTWESNPRF, -O_TCollEnum_Default,
                           -FC.O_THFC_Default}) :
  R_int_WOTSTW(A, O_Game34_WOTSTWES_AltX, FC.O_THFC_Default).O_wrap.query
  ~ R_TCOLL(A, O_TCollEnum_Default, FC.O_THFC_Default).O_wrap.query :
     ={wad, m}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = O_TCollEnum_Default.ps{2}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{1}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{2}
  /\ s4_qs_ts O_MEUFGCMA_WOTSTWESNPRF.qs{1} O_TCollEnum_Default.ts{2}
  /\ s4_wads_ts R_int_WOTSTW.O_wrap.wads{1} O_TCollEnum_Default.ts{2}
  /\ s4_ts_enc O_TCollEnum_Default.ts{2}
  ==>
     ={res}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = O_TCollEnum_Default.ps{2}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{1}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{2}
  /\ s4_qs_ts O_MEUFGCMA_WOTSTWESNPRF.qs{1} O_TCollEnum_Default.ts{2}
  /\ s4_wads_ts R_int_WOTSTW.O_wrap.wads{1} O_TCollEnum_Default.ts{2}
  /\ s4_ts_enc O_TCollEnum_Default.ts{2}.
proof.
proc.
inline{1} O_Game34_WOTSTWES_AltX.query.
inline{2} O_TCollEnum_Default.query.
inline{1} FC.O_THFC_Default.query.
inline{2} FC.O_THFC_Default.query.
sp.
(* Left statements 1..20 (grind, d-fetch, the AltX prologue) against nothing on
   the right.  The grind's whole job is `c{1} = grindC`, whence `m0{1}` is the
   target oracle's own digest and `em{1} = em{2}`. *)
seq 20 0 : (
     ={m, wad}
  /\ ad0{1} = ad{2}
  /\ ad{2} = WAddress.val wad{2}
  /\ valid_wadrs ad{2}
  /\ c{1} = c{2}
  /\ em{1} = em{2}
  /\ em{1} = encode_msgWOTS m0{1}
  /\ sk{1} = [] /\ sig{1} = [] /\ sk{2} = [] /\ sig{2} = []
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = O_TCollEnum_Default.ps{2}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{1}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{2}
  /\ s4_qs_ts_pend O_MEUFGCMA_WOTSTWESNPRF.qs{1} m0{1} O_TCollEnum_Default.ts{2}
  /\ s4_wads_ts_pend R_int_WOTSTW.O_wrap.wads{1} ad0{1} O_TCollEnum_Default.ts{2}
  /\ s4_ts_enc O_TCollEnum_Default.ts{2}).
+ wp.
  while{1} (
       ad{1} = WAddress.val wad{1}
    /\ (found{1} => c{1} = grindC FC.O_THFC_Default.pp{1} ad{1} m{1})
    /\ (!found{1} => c{1} = witness)
    /\ (!found{1} =>
          head witness
            (filter (fun (cc : cntr) =>
                       predC (ThC FC.O_THFC_Default.pp{1} ad{1} m{1} cc)) cs{1})
          = grindC FC.O_THFC_Default.pp{1} ad{1} m{1}))
    (size cs{1}).
  - move=> &2 z; wp; skip => /> &hr *; rewrite !ThC_E /=.
    smt(STCRC_WC.G.head_filter_ne size_behead size_ge0 size_eq0).
  skip => /> &1 &2 ts_R hqt hwt hte c_L cs_L found_L.
  split; first by move=> _ _ _; smt(size_eq0 size_ge0).
  move=> hexit hf1 hf2 hf3.
  have hc : c_L = grindC FC.O_THFC_Default.pp{2} (WAddress.val wad{2}) m{2}
    by smt(grindC_filter size_eq0 size_ge0).
  rewrite hc !ThC_E /=.
  (* ONE `split` first, not `do ! split`: `=> />` unfolded `valid_wadrs` into
     its raw index-list conjunction, which `do !` would shred into a dozen
     goals and mis-align every bullet below. *)
  split; first by smt(WAddress.valP).
  do ! split.
  - exact (s4_qs_ts_open _ _ _ _ _ _ _ hqt).
  - exact (s4_wads_ts_open _ _ _ _ _ _ _ hwt).
  exact (s4_ts_enc_rcons_enc _ _ _ _ _ hte).
(* -- the public-key chain loop: one `cf` on the left, an `OC` walk on the
      right.  `while{2}` unrolls the walk; nothing else differs. -- *)
wp.
while (
     ={sig, m, wad}
  /\ pk0{1} = pk{2}
  /\ em{1} = em{2}
  /\ ad0{1} = ad{2}
  /\ ad{2} = WAddress.val wad{2}
  /\ valid_wadrs ad{2}
  /\ 0 <= size pk0{1} <= len
  /\ c{1} = c{2}
  /\ em{1} = encode_msgWOTS m0{1}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = O_TCollEnum_Default.ps{2}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{1}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{2}
  /\ s4_qs_ts_pend O_MEUFGCMA_WOTSTWESNPRF.qs{1} m0{1} O_TCollEnum_Default.ts{2}
  /\ s4_wads_ts_pend R_int_WOTSTW.O_wrap.wads{1} ad0{1} O_TCollEnum_Default.ts{2}
  /\ s4_ts_enc O_TCollEnum_Default.ts{2}).
+ wp.
  while{2} (
       ad{2} = WAddress.val wad{2}
    /\ valid_wadrs ad{2}
    /\ 0 <= size pk{2} < len
    /\ em_ele{2} = BaseW.val em{2}.[size pk{2}]
    /\ em_ele{2} <= j{2}
    /\ j{2} <= w - 1
    /\ pk_ele{2} = cf FC.O_THFC_Default.pp{2} (set_chidx ad{2} (size pk{2}))
                      em_ele{2} (j{2} - em_ele{2}) (DigestBlock.val sig_ele{2}))
    (w - 1 - j{2}).
  - move=> &1 z; auto => /> *; smt(pk_walk_step BaseW.valP).
  auto => /> *; smt(pk_walk_base BaseW.valP size_rcons).
(* -- the signature loop: identical sampling, then one `cf ... 1` on the left
      against one `OC` step on the right (the `em_ele = 0` branch is literally
      the same assignment on both sides). -- *)
wp.
while (
     ={sk, sig, m, wad}
  /\ em{1} = em{2}
  /\ ad0{1} = ad{2}
  /\ ad{2} = WAddress.val wad{2}
  /\ valid_wadrs ad{2}
  /\ 0 <= size sig{1} <= len
  /\ c{1} = c{2}
  /\ em{1} = encode_msgWOTS m0{1}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = O_TCollEnum_Default.ps{2}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{1}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{2}
  /\ s4_qs_ts_pend O_MEUFGCMA_WOTSTWESNPRF.qs{1} m0{1} O_TCollEnum_Default.ts{2}
  /\ s4_wads_ts_pend R_int_WOTSTW.O_wrap.wads{1} ad0{1} O_TCollEnum_Default.ts{2}
  /\ s4_ts_enc O_TCollEnum_Default.ts{2}).
+ auto => /> *; smt(sig_walk_step BaseW.valP size_rcons).
skip => /> *; smt(ge2_len s4_qs_ts_close s4_wads_ts_close).
qed.

(* ==========================================================================
   4.  A's CHOOSE PHASE, PERFECTLY SIMULATED.

   `proc INV` discharges the caller with `pre => INV` and `INV => post`, so
   EVERY conjunct `query_eq_badenc` carries in its pre/post must ALSO be in the
   invariant here.  (`cdrafts-split/WOTS_C_Interactive.ec`'s `choose_tw` records what
   happens otherwise: `proc INV` leaves a first-order implication as goal #1 and
   the following `conseq` lands on it, producing a misleading
   "do not know how to combine equivF" error.)

   The collection hook is the SAME module on both sides and its answer is
   `fc (size x) pp tw x`, so it needs only the seed agreement -- the accumulated
   `tws` lists are already unequal here and stay out of the invariant.
   ========================================================================== *)
equiv choose_eq_badenc
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_WOTSTW, -R_TCOLL, -O_MEUFGCMA_WOTSC_Default,
                           -O_MEUFGCMA_WOTSTWESNPRF, -O_TCollEnum_Default,
                           -FC.O_THFC_Default}) :
  A(R_int_WOTSTW(A, O_Game34_WOTSTWES_AltX, FC.O_THFC_Default).O_wrap,
    FC.O_THFC_Default).choose
  ~ A(R_TCOLL(A, O_TCollEnum_Default, FC.O_THFC_Default).O_wrap,
      FC.O_THFC_Default).choose :
     ={glob A}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = O_TCollEnum_Default.ps{2}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{1}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{2}
  /\ s4_qs_ts O_MEUFGCMA_WOTSTWESNPRF.qs{1} O_TCollEnum_Default.ts{2}
  /\ s4_wads_ts R_int_WOTSTW.O_wrap.wads{1} O_TCollEnum_Default.ts{2}
  /\ s4_ts_enc O_TCollEnum_Default.ts{2}
  ==>
     ={glob A}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = O_TCollEnum_Default.ps{2}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{1}
  /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{2}
  /\ s4_qs_ts O_MEUFGCMA_WOTSTWESNPRF.qs{1} O_TCollEnum_Default.ts{2}
  /\ s4_wads_ts R_int_WOTSTW.O_wrap.wads{1} O_TCollEnum_Default.ts{2}
  /\ s4_ts_enc O_TCollEnum_Default.ts{2}.
proof.
proc (   O_MEUFGCMA_WOTSTWESNPRF.ps{1} = O_TCollEnum_Default.ps{2}
      /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{1}
      /\ O_MEUFGCMA_WOTSTWESNPRF.ps{1} = FC.O_THFC_Default.pp{2}
      /\ s4_qs_ts O_MEUFGCMA_WOTSTWESNPRF.qs{1} O_TCollEnum_Default.ts{2}
      /\ s4_wads_ts R_int_WOTSTW.O_wrap.wads{1} O_TCollEnum_Default.ts{2}
      /\ s4_ts_enc O_TCollEnum_Default.ts{2}) => //.
+ conseq (query_eq_badenc A) => //.
+ by proc; auto => />.
qed.

(* A's FORGE phase is relayed verbatim: its oracle set is `{}`
   (`cdrafts-split/WOTS_C_Scheme.ec:143`), so the two oracle instantiations run
   identical code. *)
equiv forge_eq_badenc
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_WOTSTW, -R_TCOLL, -O_MEUFGCMA_WOTSC_Default,
                           -O_MEUFGCMA_WOTSTWESNPRF, -O_TCollEnum_Default,
                           -FC.O_THFC_Default}) :
  A(R_int_WOTSTW(A, O_Game34_WOTSTWES_AltX, FC.O_THFC_Default).O_wrap,
    FC.O_THFC_Default).forge
  ~ A(R_TCOLL(A, O_TCollEnum_Default, FC.O_THFC_Default).O_wrap,
      FC.O_THFC_Default).forge :
    ={glob A, arg} ==> ={glob A, res}.
proof. proc true => //. qed.

(* ==========================================================================
   5.  STEP 4 -- THE PROBABILITY INEQUALITY.
   ========================================================================== *)
section Step4.

declare module A <: Adv_MEUFGCMA_WOTSC{-O_MEUFGCMA_WOTSTWESNPRF,
                                       -O_MEUFGCMA_WOTSC_Default,
                                       -R_int_WOTSTW, -R_TCOLL,
                                       -FC.O_THFC_Default,
                                       -O_TCollEnum_Default}.

lemma badenc_le_tcoll &m :
     c <= p_tgts
  => Pr[Game4_WOTSTWES_BadEnc(R_int_WOTSTW(A)).main() @ &m
          : res /\ BadEncFlag.badenc]
     <= Pr[T_COLL_RES_ENUM(R_TCOLL(A), O_TCollEnum_Default,
                           FC.O_THFC_Default).main() @ &m : res].
proof.
move=> le_c_ptgts.
byequiv (_ : ={glob A} ==> (res{1} /\ BadEncFlag.badenc{1}) => res{2}) => //.
proc.
inline *.
wp.
while{1} (true) (len - size pkWOTS0{1}).
+ by move=> &2 z; auto; smt(size_rcons).
wp.
call (forge_eq_badenc A).
wp.
call (choose_eq_badenc A).
(* Residual read off `experiments/wots-badenc/red/dump.sh`, not guessed: after `auto => />` it is a single
   pure formula -- the left game's win conjuncts as hypotheses, the right game's
   as the conclusion -- i.e. exactly `s4_transfer`, consumed as a proof term. *)
auto => /> psL hin hq0 hw0 ht0 wads_L qs_L tws_L ts_R hqt hwt hte rR pk0_L.
split; first by smt(size_ge0).
move=> _ hge0sz hlec hge0i hltisz hpk hfresh huniq hdisj hnochw hP hP' hcol.
have hpre :
     size qs_L <= c
  /\ 0 <= rR.`1 < size qs_L
  /\ ThC psL (WAddress.val (nth witness wads_L rR.`1)) rR.`2 rR.`3.`2
     <> (nth witness qs_L rR.`1).`2
  /\ P (nth witness qs_L rR.`1).`2
  /\ P (ThC psL (WAddress.val (nth witness wads_L rR.`1)) rR.`2 rR.`3.`2)
  /\   encode_msgWOTS (nth witness qs_L rR.`1).`2
     = encode_msgWOTS
         (ThC psL (WAddress.val (nth witness wads_L rR.`1)) rR.`2 rR.`3.`2)
  by smt().
have := s4_transfer psL qs_L ts_R wads_L rR.`1 rR.`2 rR.`3.`2
          le_c_ptgts hqt hwt hte hpre.
smt().
qed.

end section Step4.
