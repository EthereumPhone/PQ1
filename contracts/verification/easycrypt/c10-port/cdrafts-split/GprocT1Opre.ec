(* T1 -- the OpenPRE branch for Gproc.  SCRATCH: nothing integrates into the
   certified tree until a complete unit compiles.

   Port of R_FSMDTOpenPRE_EUFCMA (base-c10-split/FORS_ES.ec:2244-2413) from
   MM45's multi-instance FORS game to C10's Gproc.  Same substitution table as
   _t2.ec / _t3.ec:
     Adv_EUFCMA_MFORSTWESNPRF   -> Adv_EUFCMA_Gproc
     O_CMA_MFORSTWESNPRF_AV     -> O_CMA_Gproc_I
     trhtype                    -> trhftype        (the FTWES clone binds it)
     s, l                       -> nr_trees 0, l'  (likewise)
     g (mco mk' m')             -> M.F.hC mk' m'   (FORS_C10.ec:211)

   ===========================================================================
   SCOPING, settled from source before any proof was attempted 2026-08-07.
   The three questions that would have been expensive to answer late:

   (1) WHICH OpenPRE GAME.  `FTWES.F_OpenPRE` -- the clone at FORS_ES.ec:470,
       with `t_smdtopenpre <- d * k * t` and `din <- ddgstblocklift`.  Its
       preimages are `dgst` drawn from the LIFTED dgstblock distribution, which
       is what the reduction needs, so MM45's F<->FP hop
       (`EqPr_SMDTOpenPRE_FOpenPRE_FPOpenPRE`, FORS_ES.ec:6426) is NOT on this
       path -- that hop exists to feed their DSPR/TCR analysis of f, not the
       bound.  Accessor shape is the same as T2's FTWES.TRHC_TCR.SM_DT_TCR_C.

       NOTE the port ALSO carries an abstract `SM_DT_OpenPRE` in
       FORS_C_TreePort.ec:186 over abstract `f_lf` / `dop_in` / `t_op`.  That is
       a different (gate-enforced, self-contained) artefact and is NOT the
       target here: its `f_lf` is abstract, whereas the T1 event below is about
       the concrete FTWES `f`.  Picking it would state a theorem about a
       function unrelated to the one the game hashes.

   (2) THE C10 DELTA AT THE LEAF LAYER: NIL, and established rather than
       assumed (T2 taught that lesson -- `hC_is_g` disproved an earlier "the
       extractor is the delta" claim).  EUF_CMA_Gproc_V sets
         leaf' = f ps (set_thtbidx adT 0 (dftidx * t + dflfidx)) (val x')
       and `cube_is_mkseq` (GprocVI.ec:26) expands the honest leaf to
         f ps (set_thtbidx adT 0 (dftidx * t + dflfidx)) (val skF[dftidx][dflfidx]).
       Same f, same tweak, same addressing as MM45.  The +C tweak lives in the
       WOTS chain (target_sum), not in the FORS leaf layer.  So `valid_OpenPRE`
       is literally "the adversary opened f at an unopened challenge position".

   (3) THE REDUCTION IS NOT SHAPED LIKE T2/T3.  Checked at ES:2244-2413 rather
       than assumed: its `O_CMA.sign` takes each secret-key element from
       `O.open(...)` instead of from a stored key, and builds auth paths out of
       `leavess`, the CHALLENGE images.  So there is no ts-accumulation loop to
       rename -- the invariant structure is about which indices have been
       opened, and `!opened` in the win condition is what `!covered` becomes.
       Budgeting this as "T2 with different names" would repeat the mistake
       that cost T2's first pass.

   (4) A FOURTH C10 DELTA, FOUND WHILE PORTING (2026-08-07) -- this one is NOT
       nil, and it is in the CMA oracle rather than in f.  MM45's O_CMA draws
       `mk <$ dmkey` and MEMOISES it per message in an `mmap`; Gproc's
       O_CMA_Gproc_I (GprocFORSC10.ec:389, flagged at :28) draws
       `mk <$ dcond dmkey (good_fors m)` and does NOT memoise.  The reduction's
       oracle has to match the game it is simulating, not the paper it is
       ported from, so `mmap` is dropped and the conditioned draw is kept.
       Correspondingly MM45's incrementally-maintained `lidxs` matches Gproc's
       end-of-game `flatten (map (fun km => M.F.hC km.`1 km.`2) ts)`, so the
       reduction accumulates `lidxs <- lidxs ++ M.F.hC mk m` on every call
       (MM45 appends only on an mmap MISS -- with no memoisation the two agree
       only if every call appends).

   FRONTIER: the reduction module is ported below and typechecks against
   FTWES.F_OpenPRE.Adv_SMDTOpenPRE.  Nothing below asserts a bound.
   =========================================================================== *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import DList DMap FMap.
require import BinaryTrees MerkleTrees.
require import BitEncoding.
import BS2Int BitChunking.
import StdBigop.Bigint StdBigop.Bigint.BIA.
import StdOrder.IntOrder.
require import SPHINCS_PLUS.
require import XmssmtCC_All.
require import RtopCSoundness.
require import FxChain.
require import GprocFORSC10.
require import GprocVI.
require import LoopTransform.

(* THE TARGET TERM, PINNED.  T2's review said the check worth doing early is
   that the event being bounded is the one the decomposition actually produces
   -- a bound on a near-miss event is unrecoverable work.  Asserting
   `T1 = T1` would compile and assert nothing (that failure mode has already
   cost this project six statements), so the pin is stated as Q minus the two
   CLOSED branches, discharged through the certified gproc_Q_decomposition.
   It therefore fails if this transcription of the OpenPRE term differs from
   the decomposition's first summand in any character. *)
lemma t1_term_pinned
  (A <: Adv_EUFCMA_Gproc{-O_CMA_Gproc_I, -EUF_CMA_Gproc_I, -EUF_CMA_Gproc_V}) &m :
    Pr[EUF_CMA_Gproc_I(A).main() @ &m : res /\ ! EUF_CMA_Gproc_I.covered]
  - Pr[EUF_CMA_Gproc_V(A).main() @ &m :
         ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
         /\ EUF_CMA_Gproc_V.valid_TRHTCR]
  - Pr[EUF_CMA_Gproc_V(A).main() @ &m :
         ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
         /\ ! EUF_CMA_Gproc_V.valid_TRHTCR]
  = Pr[EUF_CMA_Gproc_V(A).main() @ &m :
         (res /\ ! EUF_CMA_Gproc_V.covered) /\ EUF_CMA_Gproc_V.valid_OpenPRE].
proof. by rewrite (gproc_Q_decomposition A &m); ring. qed.

(* ---------------------------------------------------------------------------
   THE REDUCTION.  Port of R_FSMDTOpenPRE_EUFCMA (FORS_ES.ec:2244-2413).

   Shape, which is what makes it unlike T2/T3: `pick()` gets NO oracle access
   at all (the module type restricts it to `{}`), so it only enumerates the
   leaf tweaks in flattened order; the challenger then samples the hidden
   preimages and hands back their images as `leavess`.  `find` therefore has to
   BUILD the public key out of challenge images rather than out of a secret
   key, and the CMA oracle serves each requested secret-key element with
   `O.open`.  The flattened index

     cidx = tidx * l' * k * t + kpidx * k * t + tree * t + leaf

   is the single place the two orderings have to agree: `pick` emits the
   tweaks in exactly this order, so `O.open cidx` returns the preimage of the
   leaf that tweak addresses.  A disagreement here is silent -- it would still
   typecheck and still produce a signature -- so it is the first thing to
   verify when the bound is attempted.
   --------------------------------------------------------------------------- *)
module (R_OPRE_Gproc (A : Adv_EUFCMA_Gproc) : FTWES.F_OpenPRE.Adv_SMDTOpenPRE)
       (O : FTWES.F_OpenPRE.Oracle_SMDTOpenPRE) = {
  var ps : pseed
  var ad : adrs
  var lidxs : (int * int * int) list
  var leavess : dgstblock list

  (* CMA oracle handed to the Gproc adversary.  Mirrors O_CMA_Gproc_I.sign
     (GprocFORSC10.ec:381-399) -- INCLUDING the conditioned, non-memoised mk
     draw -- except that the secret-key element comes from O.open and the
     authentication path is built from the challenge images. *)
  module O_CMA : SOracle_CMA_Gproc = {
    proc sign(m : msg) : sigGproc = {
      var mk : mkey;
      var cm : FTWES.msgFORSTW;
      var idx : index;
      var tidx, kpidx, lidx, base : int;
      var bslidx : bool list;
      var sigFORSTW : (dgstblock * FTWES.apFORSTW) list;
      var leaves : dgstblock list;
      var skFORS_ele : dgst;
      var ap : FTWES.apFORSTW;

      mk <$ dcond dmkey (good_fors m);
      lidxs <- lidxs ++ M.F.hC mk m;

      (cm, idx) <- FTWES.mco mk m;
      (tidx, kpidx) <- edivz (Index.val idx) l';

      sigFORSTW <- [];
      while (size sigFORSTW < k) {
        bslidx <- take a (drop (a * (size sigFORSTW)) (FTWES.BLKAL.val cm));
        lidx <- bs2int (rev bslidx);
        base <- tidx * l' * k * t + kpidx * k * t + size sigFORSTW * t;
        skFORS_ele <@ O.open(base + lidx);
        leaves <- take t (drop base leavess);
        ap <- FTWES.cons_ap_trh ps
                (set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx)
                (list2tree leaves) lidx (size sigFORSTW);
        sigFORSTW <- rcons sigFORSTW (DigestBlock.insubd skFORS_ele, ap);
      }

      return (mk, FTWES.DBAPKL.insubd sigFORSTW);
    }
  }

  proc pick() : adrs list = {
    var adl : adrs list;
    var tidx, kpidx, tbidx : int;

    ad <- adz;

    adl <- [];
    tidx <- 0;
    while (tidx < nr_trees 0) {
      kpidx <- 0;
      while (kpidx < l') {
        tbidx <- 0;
        while (tbidx < k * t) {
          adl <- rcons adl
                   (set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) tidx)
                                           kpidx) 0 tbidx);
          tbidx <- tbidx + 1;
        }
        kpidx <- kpidx + 1;
      }
      tidx <- tidx + 1;
    }

    return adl;
  }

  proc find(ps_init : pseed, leavess_init : dgstblock list) : int * dgst = {
    var pkFORSs : FTWES.pkFORS list list;
    var pkFORSl : FTWES.pkFORS list;
    var pkFORS : FTWES.pkFORS;
    var roots : dgstblock list;
    var root : dgstblock;
    var leaves : dgstblock list;
    var adT : adrs;
    var m' : msg;
    var mk' : mkey;
    var sigFORSTW' : FTWES.sigFORSTW;
    var sig' : sigGproc;
    var lidxs' : (int * int * int) list;
    var tidx, kpidx, dfidx, dftidx, dflfidx, cidx : int;
    var idx' : index;
    var cm' : FTWES.msgFORSTW;
    var x' : dgstblock;
    var ap' : FTWES.apFORSTW;

    ps <- ps_init;
    leavess <- leavess_init;
    lidxs <- [];

    (* Public key from the CHALLENGE images, instance by instance. *)
    pkFORSs <- [];
    while (size pkFORSs < nr_trees 0) {
      pkFORSl <- [];
      while (size pkFORSl < l') {
        adT <- set_kpidx (set_tidx (set_typeidx ad trhftype) (size pkFORSs))
                         (size pkFORSl);
        roots <- [];
        while (size roots < k) {
          leaves <- take t (drop (size pkFORSs * l' * k * t
                                  + size pkFORSl * k * t
                                  + size roots * t) leavess);
          root <- FTWES.val_bt_trh ps adT (list2tree leaves) (size roots);
          roots <- rcons roots root;
        }
        pkFORS <- trco ps (set_kpidx (set_typeidx adT trcotype)
                                     (FTWES.get_kpidx adT))
                          (flatten (map DigestBlock.val roots));
        pkFORSl <- rcons pkFORSl pkFORS;
      }
      pkFORSs <- rcons pkFORSs pkFORSl;
    }

    (m', sig') <@ A(O_CMA).forge((pkFORSs, ps, ad));

    (mk', sigFORSTW') <- sig';
    (cm', idx') <- FTWES.mco mk' m';

    (* g (mco mk' m') is C10's M.F.hC mk' m' (FORS_C10.ec:211). *)
    lidxs' <- M.F.hC mk' m';

    (dfidx, dftidx, dflfidx) <-
      nth witness lidxs' (find (fun i => ! (i \in lidxs)) lidxs');

    (x', ap') <- nth witness (FTWES.DBAPKL.val sigFORSTW') dftidx;

    (tidx, kpidx) <- edivz (Index.val idx') l';

    (* Same flattening as `pick` emits, so this indexes the intended target. *)
    cidx <- tidx * l' * k * t + kpidx * k * t + dftidx * t + dflfidx;

    return (cidx, DigestBlock.val x');
  }
}.


(* ===========================================================================
   LOOP REFORMATTING for the challenger's init.

   The obstacle the frontier note predicted, now identified exactly: the game
   side samples the FORS key in FOUR NESTED loops (GprocKg.keygen, nr_trees 0 x
   l' x k x t) while the OpenPRE challenger's O_SMDTOpenPRE_Default.init samples
   in ONE FLAT loop of length min (size tws) (l * k * t).  Sampling statements
   can only be matched pairwise, so the two nests must be brought into the same
   shape before any `rnd` correspondence can be stated.

   MM45 does this at FORS_ES.ec:2826-3160 and their machinery is `local`, so it
   is NOT exported through the FTWES clone -- verified, not assumed:
   `FTWES.O_SMDTOpenPRE_Default_ILN` is an unknown procedure.  It has to be
   re-derived here.  What is reusable is the part that matters: `AdvLoop` /
   `Loop` / `loop1_loopk` come from EasyCrypt's OWN stdlib
   (theories/looping/LoopTransform.ec), so this is instantiating a generic
   loop-transformation theory rather than hand-rolling an induction.

   Counts, via the clone at SPHINCS_PLUS.ec:509 (s <- nr_trees 0, l <- l',
   d <- l): t_smdtopenpre = l * k * t, and FTWES.dval gives
   l = nr_trees 0 * l', so the flat length and the nested product agree. *)
clone import ExactIter as EI_OPRE with
  type t <- dgstblock list,
  op c <- 1,
  op step <- 1
  proof *.
  realize c_gt0 by trivial.
  realize step_gt0 by trivial.

(* Body of the flat loop, as an AdvLoop so Loop(.) can restructure it. *)
module O_OPRE_LoopBody : AdvLoop = {
  import var FTWES.F_OpenPRE.O_SMDTOpenPRE_Default
  var tws : adrs list

  proc body(ys : dgstblock list, i : int) : dgstblock list = {
    var x : dgst;
    var y : dgstblock;
    var tw : adrs;
    var twy : adrs * dgstblock;

    tw <- nth witness tws i;
    x <$ FTWES.ddgstblocklift;
    y <- f pp tw x;
    twy <- (tw, y);
    xs <- rcons xs x;
    ys <- rcons ys y;
    ts <- rcons ts twy;

    return ys;
  }
}.

(* Stage 1 of the nesting chain: the original init, with its body factored out
   through Loop(.).loop1.  Nothing is nested yet -- this only puts the loop in
   the form the stdlib transformation applies to. *)
module O_OPRE_CL = {
  import var FTWES.F_OpenPRE.O_SMDTOpenPRE_Default
  import var O_OPRE_LoopBody

  proc init1(pp_init : pseed, tws_init : adrs list) : dgstblock list = {
    var ys : dgstblock list;

    tws <- tws_init;
    pp <- pp_init;
    ts <- [];
    xs <- [];
    os <- [];
    ys <- [];

    ys <@ Loop(O_OPRE_LoopBody).loop1(ys, l * k * t);

    return ys;
  }
}.

equiv Eqv_OPRE_Init_Orig_CL1 :
  FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.init ~ O_OPRE_CL.init1 :
    ={arg} /\ l * k * t <= size tws_init{1}
    ==> ={res, glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default}.
proof.
proc.
inline{2} 7.
wp => /=.
(* `t` is BOTH the stdlib loop's state variable and FORS's constant; the
   constant has to be written SPHINCS_PLUS.t here or it resolves to the
   program variable (MM45 writes Top.t for exactly this reason). *)
while (   ={glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default}
       /\ ys{1} = t{2}
       /\ tws_init{1} = O_OPRE_LoopBody.tws{2}
       /\ n{2} = l * k * SPHINCS_PLUS.t
       /\ l * k * SPHINCS_PLUS.t <= size O_OPRE_LoopBody.tws{2}
       /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{1} = i{2}
       /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{1} <= l * k * SPHINCS_PLUS.t).
+ inline{2} 1.
  by wp; rnd; wp; skip => />; smt(size_rcons).
by wp; skip => />; smt(FTWES.ge1_d ge1_k ge2_t).
qed.

(* Stage 2: peel the outermost level (nr_trees 0) off the flat loop.  The
   nesting itself is the stdlib's `loop1_loopk`, instantiated at
   (ys, nr_trees 0, l' * k * t); its side condition is exactly
   l * k * t = nr_trees 0 * (l' * k * t), i.e. FTWES.dval. *)
module O_OPRE_LoopBodyNest1 : AdvLoop = {
  import var FTWES.F_OpenPRE.O_SMDTOpenPRE_Default
  import var O_OPRE_LoopBody
  var i : int

  proc body(ys : dgstblock list, j : int) : dgstblock list = {
    var x : dgst;
    var y : dgstblock;
    var tw : adrs;
    var twy : adrs * dgstblock;

    tw <- nth witness tws (i * l' * k * SPHINCS_PLUS.t + j);
    x <$ FTWES.ddgstblocklift;
    y <- f pp tw x;
    twy <- (tw, y);
    xs <- rcons xs x;
    ys <- rcons ys y;
    ts <- rcons ts twy;

    return ys;
  }
}.

module O_OPRE_CL2 = {
  import var FTWES.F_OpenPRE.O_SMDTOpenPRE_Default
  import var O_OPRE_LoopBody
  import var O_OPRE_LoopBodyNest1

  proc init2(pp_init : pseed, tws_init : adrs list) : dgstblock list = {
    var ys : dgstblock list;

    tws <- tws_init;
    pp <- pp_init;
    ts <- [];
    xs <- [];
    os <- [];
    ys <- [];

    i <- 0;
    while (i < nr_trees 0) {
      ys <@ Loop(O_OPRE_LoopBodyNest1).loop1(ys, l' * k * SPHINCS_PLUS.t);
      i <- i + 1;
    }

    return ys;
  }
}.

equiv Eqv_OPRE_Init_CL1_CL2 :
  O_OPRE_CL.init1 ~ O_OPRE_CL2.init2 :
    ={arg} ==> ={res, glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default}.
proof.
proc.
rewrite equiv [{1} 7 (loop1_loopk O_OPRE_LoopBody)
                     (ys, nr_trees 0, l' * k * SPHINCS_PLUS.t :@ ys)].
+ wp; skip => />; rewrite FTWES.dval;
    smt(FTWES.ge1_s FTWES.ge1_l ge1_k ge2_t).
inline{1} 7.
wp => /=.
while (   ={glob O_OPRE_LoopBody}
       /\ i{1} = O_OPRE_LoopBodyNest1.i{2}
       /\ t{1} = ys{2}
       /\ tws_init{1} = O_OPRE_LoopBody.tws{2}
       /\ n{1} = nr_trees 0
       /\ k{1} = l' * k * SPHINCS_PLUS.t).
+ inline{2} 1.
  wp => /=.
  while (   ={glob O_OPRE_LoopBody, t}
         /\ j{1} = i{2}
         /\ i{1} = O_OPRE_LoopBodyNest1.i{2}
         /\ k{1} = n{2}
         /\ k{1} = l' * k * SPHINCS_PLUS.t).
  - inline{1} 1; inline{2} 1.
    by wp; rnd; wp; skip => /> /#.
  by wp; skip => /> /#.
by wp; skip => /> /#.
qed.

(* Stage 3: peel the l' level. *)
module O_OPRE_LoopBodyNest2 : AdvLoop = {
  import var FTWES.F_OpenPRE.O_SMDTOpenPRE_Default
  import var O_OPRE_LoopBody
  import var O_OPRE_LoopBodyNest1
  var j : int

  proc body(ys : dgstblock list, u : int) : dgstblock list = {
    var x : dgst;
    var y : dgstblock;
    var tw : adrs;
    var twy : adrs * dgstblock;

    tw <- nth witness tws (i * l' * k * SPHINCS_PLUS.t
                           + j * k * SPHINCS_PLUS.t + u);
    x <$ FTWES.ddgstblocklift;
    y <- f pp tw x;
    twy <- (tw, y);
    xs <- rcons xs x;
    ys <- rcons ys y;
    ts <- rcons ts twy;

    return ys;
  }
}.

module O_OPRE_CL3 = {
  import var FTWES.F_OpenPRE.O_SMDTOpenPRE_Default
  import var O_OPRE_LoopBody
  import var O_OPRE_LoopBodyNest1
  import var O_OPRE_LoopBodyNest2

  proc init3(pp_init : pseed, tws_init : adrs list) : dgstblock list = {
    var ys : dgstblock list;

    tws <- tws_init;
    pp <- pp_init;
    ts <- [];
    xs <- [];
    os <- [];
    ys <- [];

    i <- 0;
    while (i < nr_trees 0) {
      j <- 0;
      while (j < l') {
        ys <@ Loop(O_OPRE_LoopBodyNest2).loop1(ys, k * SPHINCS_PLUS.t);
        j <- j + 1;
      }
      i <- i + 1;
    }

    return ys;
  }
}.

equiv Eqv_OPRE_Init_CL2_CL3 :
  O_OPRE_CL2.init2 ~ O_OPRE_CL3.init3 :
    ={arg} ==> ={res, glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default}.
proof.
proc.
while (={glob O_OPRE_LoopBodyNest1, ys}).
+ rewrite equiv [{1} 1 (loop1_loopk O_OPRE_LoopBodyNest1)
                       (ys, l', k * SPHINCS_PLUS.t :@ ys)].
  - by wp; skip => />; smt(ge1_k ge2_t).
  inline{1} 1.
  wp => /=.
  while (   ={glob O_OPRE_LoopBodyNest1}
         /\ i{1} = O_OPRE_LoopBodyNest2.j{2}
         /\ k{1} = k * SPHINCS_PLUS.t
         /\ n{1} = l'
         /\ t{1} = ys{2}).
  - inline{2} 1.
    wp => /=.
    while (   ={glob O_OPRE_LoopBodyNest1, t}
           /\ i{1} = O_OPRE_LoopBodyNest2.j{2}
           /\ k{1} = k * SPHINCS_PLUS.t
           /\ n{1} = l'
           /\ j{1} = i{2}
           /\ n{2} = k * SPHINCS_PLUS.t).
    * inline{1} 1; inline{2} 1.
      wp; rnd; wp; skip => /> /#.
    by wp; skip.
  by wp; skip => /> /#.
by wp; skip => /> /#.
qed.

(* Stage 4: the fully nested init -- the shape GprocKg.keygen samples in. *)
module O_OPRE_ILN = {
  import var FTWES.F_OpenPRE.O_SMDTOpenPRE_Default

  proc init(pp_init : pseed, tws_init : adrs list) : dgstblock list = {
    var x : dgst;
    var y : dgstblock;
    var ys : dgstblock list;
    var tw : adrs;
    var twy : adrs * dgstblock;
    var i, j, u, v : int;

    pp <- pp_init;
    ts <- [];
    xs <- [];
    os <- [];
    ys <- [];
    i <- 0;
    while (i < nr_trees 0) {
      j <- 0;
      while (j < l') {
        u <- 0;
        while (u < k) {
          v <- 0;
          while (v < SPHINCS_PLUS.t) {
            tw <- nth witness tws_init (i * l' * k * SPHINCS_PLUS.t
                                        + j * k * SPHINCS_PLUS.t
                                        + u * SPHINCS_PLUS.t + v);
            x <$ FTWES.ddgstblocklift;
            y <- f pp tw x;
            twy <- (tw, y);
            xs <- rcons xs x;
            ys <- rcons ys y;
            ts <- rcons ts twy;
            v <- v + 1;
          }
          u <- u + 1;
        }
        j <- j + 1;
      }
      i <- i + 1;
    }

    return ys;
  }
}.

equiv Eqv_OPRE_Init_CL3_ILN :
  O_OPRE_CL3.init3 ~ O_OPRE_ILN.init :
    ={arg} ==> ={res, glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default}.
proof.
proc.
while (   ={glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default, ys}
       /\ O_OPRE_LoopBodyNest1.i{1} = i{2}
       /\ O_OPRE_LoopBody.tws{1} = tws_init{2}).
+ wp => /=.
  while (   #pre
         /\ O_OPRE_LoopBodyNest2.j{1} = j{2}).
  - rewrite equiv [{1} 1 (loop1_loopk O_OPRE_LoopBodyNest2)
                         (ys, k, SPHINCS_PLUS.t :@ ys)].
    * by wp; skip => />; smt(ge2_t).
    inline{1} 1.
    wp => /=.
    while (   ={glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default}
           /\ O_OPRE_LoopBody.tws{1} = tws_init{2}
           /\ O_OPRE_LoopBodyNest1.i{1} = i{2}
           /\ O_OPRE_LoopBodyNest2.j{1} = j{2}
           /\ i{1} = u{2}
           /\ t{1} = ys{2}
           /\ n{1} = k
           /\ k{1} = SPHINCS_PLUS.t).
    * wp => /=.
      while (   #pre
             /\ j{1} = v{2}).
      + inline{1} 1.
        by wp; rnd; wp; skip => /> /#.
      by wp; skip => /> /#.
    by wp; skip => /> /#.
  by wp; skip => /> /#.
by wp; skip => /> /#.
qed.

(* The composed reformatting: the challenger's flat init is the nested one. *)
equiv Eqv_OPRE_Init_Orig_ILN :
  FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.init ~ O_OPRE_ILN.init :
    ={arg} /\ l * k * SPHINCS_PLUS.t <= size tws_init{1}
    ==> ={res, glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default}.
proof.
transitivity O_OPRE_CL.init1
             (={arg} /\ l * k * SPHINCS_PLUS.t <= size tws_init{1}
              ==> ={res, glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default})
             (={arg} ==> ={res, glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default})
             => [/# | // | |].
+ by apply Eqv_OPRE_Init_Orig_CL1.
transitivity O_OPRE_CL2.init2
             (={arg} ==> ={res, glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default})
             (={arg} ==> ={res, glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default})
             => [/# | // | |].
+ by apply Eqv_OPRE_Init_CL1_CL2.
transitivity O_OPRE_CL3.init3
             (={arg} ==> ={res, glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default})
             (={arg} ==> ={res, glob FTWES.F_OpenPRE.O_SMDTOpenPRE_Default})
             => [/# | // | |].
+ by apply Eqv_OPRE_Init_CL2_CL3.
by apply Eqv_OPRE_Init_CL3_ILN.
qed.

(* Two pointwise rcons equations.  `nth_rcons` states all three cases at once
   behind an `if`, which smt will not use as a rewrite rule under three layers
   of nth; split into the two directed equations it can actually apply. *)
lemma nth_rcons_lt (s : 'a list) (x : 'a) (i : int) :
  0 <= i < size s => nth witness (rcons s x) i = nth witness s i.
proof. by move=> h; rewrite nth_rcons; smt(). qed.

lemma nth_rcons_eq (s : 'a list) (x : 'a) :
  nth witness (rcons s x) (size s) = x.
proof. by rewrite nth_rcons. qed.

(* The level fold, as a standalone lemma.  Extracting it is deliberate: inside
   the equiv it is a case split on i = n buried under three layers of `nth` and
   a DigestBlock.val, and two widened smt hint lists failed to find it.  Stated
   alone it is four lines, and -- more to the point -- it can be checked on its
   own instead of only ever being exercised through a 900-line proof. *)
lemma fold_rcons_corr (xs : dgst list) (skn : FTWES.skFORS list list)
                      (skl : FTWES.skFORS list) (n : int) :
     size skn = n
  => 0 <= n
  => (forall (i j u v : int),
        0 <= i < n => 0 <= j < l' => 0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
        nth witness xs (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                        + u * SPHINCS_PLUS.t + v)
        = DigestBlock.val
            (nth witness (nth witness (FTWES.DBLLKTL.val
              (nth witness (nth witness skn i) j)) u) v))
  => (forall (j u v : int),
        0 <= j < l' => 0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
        nth witness xs (n * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                        + u * SPHINCS_PLUS.t + v)
        = DigestBlock.val
            (nth witness (nth witness (FTWES.DBLLKTL.val
              (nth witness skl j)) u) v))
  => (forall (i j u v : int),
        0 <= i < n + 1 => 0 <= j < l' => 0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
        nth witness xs (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                        + u * SPHINCS_PLUS.t + v)
        = DigestBlock.val
            (nth witness (nth witness (FTWES.DBLLKTL.val
              (nth witness (nth witness (rcons skn skl) i) j)) u) v)).
proof.
move=> hsz hge0 hold hcur i j u v hi hj hu hv.
case (i < n) => [hlt | hnlt].
+ have -> : nth witness (rcons skn skl) i = nth witness skn i
    by smt(nth_rcons).
  have h := hold i j u v.
  by apply h; smt().
(* i = n has to reach the INDEX expression too, not just the list lookup:
   hcur is stated at n, so rewriting only the `nth (rcons ..) i` leaves the
   goal's index at i and the apply fails. *)
have hin : i = n by smt().
have -> : nth witness (rcons skn skl) i = skl by smt(nth_rcons).
rewrite hin.
have h := hcur j u v.
by apply h; smt().
qed.

(* The level-3 -> level-2 fold.  Same shape as fold_rcons_corr one level down,
   with the one extra step that level actually adds: the raw cube is wrapped by
   FTWES.DBLLKTL.insubd on the way up, so the j = m case needs insubdK and
   therefore needs the subtype predicate -- size cube = k and every row of
   length t.  That is why the level-3 invariant has to carry the `all` shape
   fact rather than just the sizes. *)
lemma fold_rcons_corr_j (xs : dgst list) (skl : FTWES.skFORS list)
                        (cube : dgstblock list list) (base m : int) :
     size skl = m
  => 0 <= m
  => size cube = k
  => all (fun (ls : dgstblock list) => size ls = SPHINCS_PLUS.t) cube
  => (forall (j u v : int),
        0 <= j < m => 0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
        nth witness xs (base + j * k * SPHINCS_PLUS.t + u * SPHINCS_PLUS.t + v)
        = DigestBlock.val
            (nth witness (nth witness (FTWES.DBLLKTL.val (nth witness skl j)) u) v))
  => (forall (u v : int),
        0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
        nth witness xs (base + m * k * SPHINCS_PLUS.t + u * SPHINCS_PLUS.t + v)
        = DigestBlock.val (nth witness (nth witness cube u) v))
  => (forall (j u v : int),
        0 <= j < m + 1 => 0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
        nth witness xs (base + j * k * SPHINCS_PLUS.t + u * SPHINCS_PLUS.t + v)
        = DigestBlock.val
            (nth witness (nth witness (FTWES.DBLLKTL.val
              (nth witness (rcons skl (FTWES.DBLLKTL.insubd cube)) j)) u) v)).
proof.
move=> hsz hge0 hck hall hold hcur j u v hj hu hv.
case (j < m) => [hlt | hnlt].
+ have -> : nth witness (rcons skl (FTWES.DBLLKTL.insubd cube)) j
          = nth witness skl j by smt(nth_rcons).
  have h := hold j u v; by apply h; smt().
have hjm : j = m by smt().
have -> : nth witness (rcons skl (FTWES.DBLLKTL.insubd cube)) j
        = FTWES.DBLLKTL.insubd cube by smt(nth_rcons).
rewrite FTWES.DBLLKTL.insubdK 1:/# hjm.
have h := hcur u v; by apply h; smt().
qed.

(* FLAT-INDEX BOUND, testing Kimi K3's read that the level-4 blocker is the
   `IDX < size xs` side condition of nth_rcons_lt, which needs multiplication
   monotonicity with l', k, t abstract.  Same role t2_off_mono_i played in T2.
   The products are re-associated to x * (l'*k*t) etc. first, so each
   monotonicity step is a single multiplication by a nonnegative atom. *)
lemma flat_idx_lt (i j u v ni nj nu nv : int) :
     0 <= i < ni => 0 <= j < l' => 0 <= u < k => 0 <= v < SPHINCS_PLUS.t
  => 0 <= nj => 0 <= nu => 0 <= nv
  => i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
     + u * SPHINCS_PLUS.t + v
   < ni * l' * k * SPHINCS_PLUS.t + nj * k * SPHINCS_PLUS.t
     + nu * SPHINCS_PLUS.t + nv.
proof.
move=> [hi0 hilt] [hj0 hjlt] [hu0 hult] [hv0 hvlt] hnj hnu hnv.
have hl : 0 < l' by smt(FTWES.ge1_l).
have hk : 0 < k by smt(ge1_k).
have ht : 0 < SPHINCS_PLUS.t by smt(ge2_t).
have hQ : 0 <= k * SPHINCS_PLUS.t by smt().
have hP : 0 <= l' * (k * SPHINCS_PLUS.t) by smt().
have f1 : forall (x : int),
  x * l' * k * SPHINCS_PLUS.t = x * (l' * (k * SPHINCS_PLUS.t))
  by move=> x; ring.
have f2 : forall (x : int),
  x * k * SPHINCS_PLUS.t = x * (k * SPHINCS_PLUS.t) by move=> x; ring.
rewrite !f1 !f2.
have b1 : i * (l' * (k * SPHINCS_PLUS.t))
       <= (ni - 1) * (l' * (k * SPHINCS_PLUS.t)) by smt(ler_wpmul2r).
have b2 : j * (k * SPHINCS_PLUS.t) <= (l' - 1) * (k * SPHINCS_PLUS.t)
  by smt(ler_wpmul2r).
have b3 : u * SPHINCS_PLUS.t <= (k - 1) * SPHINCS_PLUS.t by smt(ler_wpmul2r).
have b4 : 0 <= ni * (l' * (k * SPHINCS_PLUS.t)) by smt(ler_wpmul2r).
have key : (ni - 1) * (l' * (k * SPHINCS_PLUS.t)) + (l' - 1) * (k * SPHINCS_PLUS.t)
         + (k - 1) * SPHINCS_PLUS.t + (SPHINCS_PLUS.t - 1)
         = ni * (l' * (k * SPHINCS_PLUS.t)) - 1 by ring.
have b5 : 0 <= nj * (k * SPHINCS_PLUS.t) by smt(ler_wpmul2r).
have b6 : 0 <= nu * SPHINCS_PLUS.t by smt(ler_wpmul2r).
smt().
qed.

(* OUTER PICK LOOP -- measured findings, 2026-08-08, so the next attempt does
   not re-derive them:
     - the middle discharge's goal IS `forall &hr, pre => post`, confirmed by
       dump, so `wp; skip => &hr hpre.` then `split` is correct;
     - but the FOLD branch after that split intros as
         `move=> adl0 tbidx0 *.`
       NOT `move=> adl0 tbidx0 hinner.` -- the latter reports "nothing to
       introduce", and the error's LINE is the one to read, not the tactic you
       expect (I misattributed this to `hpre` twice);
     - carrying the previous-TREES conjunct into the inner and middle
       invariants typechecks, and its preservation in the inner body is proved
       by three grounded facts: hassoc (i*l'*k*t = i*(l'*k*t), ring), hbt (the
       telescope applied TWICE -- stride k*t inside a tree, then l'*k*t across
       trees), and hpt (the conjunct itself via nth_rcons_lt);
     - CONFIRMED by dump: after `move=> adl0 tbidx0` the goal is a
       CONJUNCTION -- part A the termination side condition, part B the fold
       proper.  THAT is why naming the inner invariant reports "nothing to
       introduce" and why `*` introduces nothing.  The working shape is
         wp; skip => &hr hpre.
         split; 1: by smt(ge1_k ge2_t).
         move=> adl0 tbidx0; split; 1: by smt().
         move=> hinner.
       With that, the inner invariant IS in context and the failure moves past
       the intro to the fold's `j0 < kpidx` branch -- which is where it now sits.
     - MEASURED next: destructuring with `move=> [# hA hB hC ...]` accepts only
       TWO names there -- the third reports "nothing to introduce" -- so the
       antecedent does not flatten into its ~8 invariant conjuncts the way `[#]`
       usually does.  Whatever shape it has, it is not the flat conjunction I
       assumed, and the next attempt should DUMP that antecedent before choosing
       a destructuring pattern rather than guessing a name count again (three
       guesses have now been spent on intro shapes in this one discharge).
     - the branch itself should still be a direct instantiation of the keypairs
       conjunct; only the extraction is unresolved. *)

(* The per-tree stride step, outer analogue of kt_step. *)
lemma lt_step (m : int) :
  (m + 1) * l' * k * SPHINCS_PLUS.t = m * l' * k * SPHINCS_PLUS.t + l' * k * SPHINCS_PLUS.t.
proof. by ring. qed.

(* The per-keypair stride step.  `(m+1)*k*t = m*k*t + k*t` is distributivity
   over THREE opaque factors, which smt does not do -- same class as the
   flat-index bounds. *)
lemma kt_step (m : int) :
  (m + 1) * k * SPHINCS_PLUS.t = m * k * SPHINCS_PLUS.t + k * SPHINCS_PLUS.t.
proof. by ring. qed.

(* The OTHER half of nth_rcons_lt's guard, which every bound lemma so far
   missed: the premise is `0 <= i < size s`, TWO-sided, and hb_out/hb_j/hb_u
   supply only the upper half.  `0 <= IDX` is a sum of PRODUCTS of nonnegatives
   -- just as nonlinear, just as unreachable for smt. *)
lemma flat_idx_ge0 (i j u v : int) :
     0 <= i => 0 <= j => 0 <= u => 0 <= v
  => 0 <= i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
          + u * SPHINCS_PLUS.t + v.
proof.
move=> hi hj hu hv.
have hl : 0 < l' by smt(FTWES.ge1_l).
have hk : 0 < k by smt(ge1_k).
have ht : 0 < SPHINCS_PLUS.t by smt(ge2_t).
by smt(mulr_ge0).
qed.

(* The one-level monotonicity telescope behind every flat-index bound: i < n
   with stride W absorbs any remainder lo <= W - 1.  Kimi K3's correction --
   flat_idx_lt above is strict only in `i` (the l'*k*t block), so it covers the
   OUTER conjunct and nothing else; the level-2 and level-3 conjuncts need
   strictness in the k*t and t blocks respectively, which is what this gives. *)
lemma flat_le (W i n lo : int) :
  0 <= W => 0 <= i => i < n => 0 <= lo => lo <= W - 1 =>
  i * W + lo <= n * W - 1.
proof.
move=> hW hi0 hin hlo0 hloW.
have h1 : i * W <= (n - 1) * W by smt(ler_wpmul2r).
have key : (n - 1) * W + (W - 1) = n * W - 1 by ring.
by smt().
qed.

(* The level-4 -> level-3 fold.  Same shape again, one level further down, and
   the simplest of the three: the cube rows are RAW dgstblock lists at this
   level, so there is no subtype wrapper and hence no insubdK step. *)
lemma fold_rcons_corr_u (xs : dgst list) (cube : dgstblock list list)
                        (row : dgstblock list) (base m : int) :
     size cube = m
  => 0 <= m
  => (forall (u v : int),
        0 <= u < m => 0 <= v < SPHINCS_PLUS.t =>
        nth witness xs (base + u * SPHINCS_PLUS.t + v)
        = DigestBlock.val (nth witness (nth witness cube u) v))
  => (forall (v : int),
        0 <= v < SPHINCS_PLUS.t =>
        nth witness xs (base + m * SPHINCS_PLUS.t + v)
        = DigestBlock.val (nth witness row v))
  => (forall (u v : int),
        0 <= u < m + 1 => 0 <= v < SPHINCS_PLUS.t =>
        nth witness xs (base + u * SPHINCS_PLUS.t + v)
        = DigestBlock.val (nth witness (nth witness (rcons cube row) u) v)).
proof.
move=> hsz hge0 hold hcur u v hu hv.
case (u < m) => [hlt | hnlt].
+ have -> : nth witness (rcons cube row) u = nth witness cube u
    by smt(nth_rcons).
  have h := hold u v; by apply h; smt().
have hum : u = m by smt().
have -> : nth witness (rcons cube row) u = row by smt(nth_rcons).
rewrite hum.
have h := hcur v; by apply h; smt().
qed.

(* leaves_eq_cube, restated over the LEAVES CHARACTERISATION instead of over
   `unzip2 ts`.  The oracle invariant carries
     nth leavess idx = f pp tweak (nth xs idx)
   and never mentions the challenger's ts, which is the natural thing for an
   ORACLE invariant to carry -- so the ts-shaped lemma does not apply there.
   Stated as a variant rather than widening Eqv_OCMA_sign's invariant with
   `leavess = unzip2 ts`, because that would move a statement digest that was
   pinned precisely so it could not drift while its proof was being written. *)
lemma leaves_eq_cube_char (leavessL : dgstblock list) (xsL : dgst list)
                          (ppv : pseed) (adTv : adrs) (skF : FTWES.skFORS)
                          (base u : int) :
     0 <= u < k
  => 0 <= base
  => base + u * SPHINCS_PLUS.t + SPHINCS_PLUS.t <= size leavessL
  => (forall (v : int), 0 <= v < SPHINCS_PLUS.t =>
        nth witness leavessL (base + u * SPHINCS_PLUS.t + v)
        = f ppv (set_thtbidx adTv 0 (u * SPHINCS_PLUS.t + v))
            (nth witness xsL (base + u * SPHINCS_PLUS.t + v)))
  => (forall (v : int), 0 <= v < SPHINCS_PLUS.t =>
        nth witness xsL (base + u * SPHINCS_PLUS.t + v)
        = DigestBlock.val
            (nth witness (nth witness (FTWES.DBLLKTL.val skF) u) v))
  => take SPHINCS_PLUS.t (drop (base + u * SPHINCS_PLUS.t) leavessL)
     = fors_leaves_op_cube skF ppv adTv u.
proof.
move=> hu hb hsz hlv hxs.
rewrite cube_is_mkseq.
have hbu : 0 <= base + u * SPHINCS_PLUS.t by smt(mulr_ge0 ge2_t).
have hszd : size (drop (base + u * SPHINCS_PLUS.t) leavessL)
          = max 0 (size leavessL - (base + u * SPHINCS_PLUS.t))
  by apply (size_drop _ _ hbu).
have hszt : size (take SPHINCS_PLUS.t
                    (drop (base + u * SPHINCS_PLUS.t) leavessL))
          = SPHINCS_PLUS.t.
+ by have := size_takel SPHINCS_PLUS.t
               (drop (base + u * SPHINCS_PLUS.t) leavessL); smt(ge2_t).
apply (eq_from_nth witness).
+ by rewrite hszt size_mkseq; smt(ge2_t).
move=> v; rewrite hszt => hv.
have hv0 : 0 <= v < SPHINCS_PLUS.t by smt().
have hnt := nth_take witness<:dgstblock> SPHINCS_PLUS.t
              (drop (base + u * SPHINCS_PLUS.t) leavessL) v _ _;
  1,2: by smt(ge2_t).
have hnd := nth_drop witness<:dgstblock> (base + u * SPHINCS_PLUS.t)
              leavessL v hbu _; 1: by smt().
rewrite hnt hnd hlv 1:// hxs 1://.
by rewrite nth_mkseq 1://.
qed.

(* The COMPANION of flat_le, and the reason both exist: flat_le bounds a flat
   index STRICTLY below a block (i*W + lo <= n*W - 1, for indexing), whereas the
   leaves slice needs the block to FIT (i*W + lo <= n*W, for a length).  Same
   telescope, one off-by-one apart; proved the same way flat_le is, since that
   shape is already known to go through. *)
lemma flat_span (W i n lo : int) :
  0 <= W => 0 <= i => i < n => lo <= W => i * W + lo <= n * W.
proof.
move=> hW hi0 hin hlo.
have h1 : i * W <= (n - 1) * W by smt(ler_wpmul2r).
have key : (n - 1) * W + W = n * W by ring.
by smt().
qed.

(* The challenger's images ARE the honest leaves.

   LHS is what find() actually slices out of `leavess`; RHS is the closed form
   keygen's gen_pkFORS produces (via genpkfors_cf_op).  Everything on the left
   of the arrow is carried verbatim by the pk-loop invariants:
     - leavess = unzip2 ts                      (so the slice is over ts)
     - ts[idx] = (tws[idx], f pp tws[idx] xs[idx])
     - tws[idx] = the honest leaf tweak         (the pick/target agreement)
     - xs[idx]  = val of the nested secret elem (the reduction's whole point)
   Stated over an ABSTRACT `base` rather than i*l'*k*t + j*k*t so the caller
   does the flat-index arithmetic once, where the bounds already live. *)
lemma leaves_eq_cube (tsL : (adrs * dgstblock) list) (xsL : dgst list)
                     (twsL : adrs list) (ppv : pseed) (adTv : adrs)
                     (skF : FTWES.skFORS) (base u : int) :
     0 <= u < k
  => 0 <= base
  => base + u * SPHINCS_PLUS.t + SPHINCS_PLUS.t <= size tsL
  => (forall (idx : int), 0 <= idx < size tsL =>
        nth witness tsL idx
        = (nth witness twsL idx,
           f ppv (nth witness twsL idx) (nth witness xsL idx)))
  => (forall (v : int), 0 <= v < SPHINCS_PLUS.t =>
        nth witness twsL (base + u * SPHINCS_PLUS.t + v)
        = set_thtbidx adTv 0 (u * SPHINCS_PLUS.t + v))
  => (forall (v : int), 0 <= v < SPHINCS_PLUS.t =>
        nth witness xsL (base + u * SPHINCS_PLUS.t + v)
        = DigestBlock.val
            (nth witness (nth witness (FTWES.DBLLKTL.val skF) u) v))
  => take SPHINCS_PLUS.t (drop (base + u * SPHINCS_PLUS.t) (unzip2 tsL))
     = fors_leaves_op_cube skF ppv adTv u.
proof.
move=> hu hb hsz hts htw hxs.
rewrite cube_is_mkseq.
(* Every stdlib fact is taken as an EXPLICIT INSTANCE rather than as a
   conditional rewrite.  `rewrite lem 1:smt(..)` does not parse (only the
   simplification tokens `//`, `/=`, `/#` are allowed in that position), and
   the `; 1: by smt()` form -- which this file uses everywhere else, side goals
   being generated BEFORE the continuation -- still leaves the side condition
   to be found under a rewrite.  Instantiating first removes both problems. *)
have hbu : 0 <= base + u * SPHINCS_PLUS.t by smt(mulr_ge0 ge2_t).
have hmap : size (unzip2 tsL) = size tsL by rewrite size_map.
have hszd : size (drop (base + u * SPHINCS_PLUS.t) (unzip2 tsL))
          = max 0 (size (unzip2 tsL) - (base + u * SPHINCS_PLUS.t))
  by apply (size_drop _ _ hbu).
have hszt : size (take SPHINCS_PLUS.t
                    (drop (base + u * SPHINCS_PLUS.t) (unzip2 tsL)))
          = SPHINCS_PLUS.t.
+ by have := size_takel SPHINCS_PLUS.t
               (drop (base + u * SPHINCS_PLUS.t) (unzip2 tsL)); smt(ge2_t).
apply (eq_from_nth witness).
+ by rewrite hszt size_mkseq; smt(ge2_t).
move=> v; rewrite hszt => hv.
have hv0 : 0 <= v < SPHINCS_PLUS.t by smt().
have hnt := nth_take witness<:dgstblock> SPHINCS_PLUS.t
              (drop (base + u * SPHINCS_PLUS.t) (unzip2 tsL)) v _ _;
  1,2: by smt(ge2_t).
have hnd := nth_drop witness<:dgstblock> (base + u * SPHINCS_PLUS.t)
              (unzip2 tsL) v hbu _; 1: by smt().
have hnm := nth_map witness<:adrs * dgstblock> witness<:dgstblock> snd
              (base + u * SPHINCS_PLUS.t + v) tsL _; 1: by smt().
have hp := hts (base + u * SPHINCS_PLUS.t + v) _; 1: by smt().
rewrite hnt hnd hnm hp /=.
by rewrite htw // hxs // nth_mkseq //.
qed.

(* The three indices are recoverable from the tweak.  Stated at a single
   breadth index w rather than the library's `u * t + v`, since the carried
   characterisation is phrased that way; instantiating the library lemmas at
   u = 0, v = w is what bridges the two. *)
lemma tweak_getidx (i j w : int) :
     valid_tidx 0 i => valid_kpidx j => valid_tbfidx 0 w
  => HA.get_idx (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
                0 w) 4 = i
  /\ HA.get_idx (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
                0 w) 2 = j
  /\ HA.get_idx (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
                0 w) 0 = w.
proof.
move=> vi vj vw.
have hw : 0 * SPHINCS_PLUS.t + w = w by ring.
have h4 := setalladztrhf_gettidx  i j 0 w vi vj _; 1: by rewrite hw.
have h2 := setalladztrhf_getkpidx i j 0 w vi vj _; 1: by rewrite hw.
have h0 := setalladztrhf_getbidx  i j 0 w vi vj _; 1: by rewrite hw.
by rewrite hw in h4; rewrite hw in h2; rewrite hw in h0; smt().
qed.

(* The three-digit decomposition of a flat index, hoisted to top level.  Not
   tidying: as a `have` inside tws_uniq its subproofs saw that lemma's
   hypotheses, so perturbing the hypothesis for a must-fail control destabilised
   smt HERE instead of at the statement -- a control whose failure site is not
   the edited one proves nothing.  Out here it is insulated, and the win
   condition needs the same decomposition for its own index bound. *)
lemma flat_decomp (N z : int) :
     0 <= z < N * l' * k * SPHINCS_PLUS.t
  => z = z %/ (l' * k * SPHINCS_PLUS.t) * l' * k * SPHINCS_PLUS.t
         + z %% (l' * k * SPHINCS_PLUS.t) %/ (k * SPHINCS_PLUS.t)
           * k * SPHINCS_PLUS.t
         + z %% (k * SPHINCS_PLUS.t)
  /\ 0 <= z %/ (l' * k * SPHINCS_PLUS.t) < N
  /\ 0 <= z %% (l' * k * SPHINCS_PLUS.t) %/ (k * SPHINCS_PLUS.t) < l'
  /\ 0 <= z %% (k * SPHINCS_PLUS.t) < k * SPHINCS_PLUS.t.
proof.
move=> hz.
have hkt : 0 < k * SPHINCS_PLUS.t by smt(ge1_k ge2_t).
have hlkt : 0 < l' * k * SPHINCS_PLUS.t by smt(FTWES.ge1_l ge1_k ge2_t).
have hdvd : (k * SPHINCS_PLUS.t) %| (l' * k * SPHINCS_PLUS.t)
  by rewrite -mulrA mulrC dvdz_mull dvdzz.
have h1 : z %% (l' * k * SPHINCS_PLUS.t) %% (k * SPHINCS_PLUS.t)
        = z %% (k * SPHINCS_PLUS.t) by rewrite modz_dvd.
have h2 : z %% (l' * k * SPHINCS_PLUS.t)
        = z %% (l' * k * SPHINCS_PLUS.t) %/ (k * SPHINCS_PLUS.t)
          * (k * SPHINCS_PLUS.t)
          + z %% (l' * k * SPHINCS_PLUS.t) %% (k * SPHINCS_PLUS.t)
  by rewrite -divz_eq.
have h3 : z = z %/ (l' * k * SPHINCS_PLUS.t) * (l' * k * SPHINCS_PLUS.t)
              + z %% (l' * k * SPHINCS_PLUS.t) by rewrite -divz_eq.
have hzw : 0 <= z < N * (l' * k * SPHINCS_PLUS.t) by smt().
split; 1: by smt().
(* Derive the quotient and remainder bounds without SMT search. *)
split; 1: by rewrite (divz_ge0 _ _ hlkt) (ltz_divLR _ _ _ hlkt).
split; 2: by split; [exact (modz_ge0 _ _ (ltr0_neq0 _ hkt))
                   | move=> _; exact (ltz_pmod _ _ hkt)].
rewrite (divz_ge0 _ _ hkt) (ltz_divLR _ _ _ hkt) mulrA.
by split; [exact (modz_ge0 _ _ (ltr0_neq0 _ hlkt))
          | move=> _; exact (ltz_pmod _ _ hlkt)].
qed.

lemma tws_uniq (twsL : adrs list) :
     size twsL = nr_trees 0 * l' * k * SPHINCS_PLUS.t
  => (forall (i j w : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
        0 <= w < k * SPHINCS_PLUS.t =>
        nth witness twsL (i * l' * k * SPHINCS_PLUS.t
                          + j * k * SPHINCS_PLUS.t + w)
        = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
            0 w)
  => uniq twsL.
proof.
move=> hsz hnth.
apply nth_uniq => u v rng_u rng_v nequv.
have hnn0 : nr_nodesf 0 = SPHINCS_PLUS.t by rewrite /nr_nodesf /t /=.
have hkt : 0 < k * SPHINCS_PLUS.t by smt(ge1_k ge2_t).
have hlkt : 0 < l' * k * SPHINCS_PLUS.t by smt(FTWES.ge1_l ge1_k ge2_t).
(* Three-way decomposition of a flat index, with its ranges.  The divisibility
   (k*t) %| (l'*k*t) is what makes the middle digit well-formed, and smt does
   not find it under a rewrite, so it is handed over. *)
have [du [rdu [rju rwu]]] := flat_decomp (nr_trees 0) u _; 1: by smt().
have [dv [rdv [rjv rwv]]] := flat_decomp (nr_trees 0) v _; 1: by smt().
rewrite {1}du {1}dv hnth 1..3:// hnth 1..3://.
(* The decomposition is injective on [0, size twsL), so u <> v forces one of
   the three digits to differ. *)
have hone :  u %/ (l' * k * SPHINCS_PLUS.t) <> v %/ (l' * k * SPHINCS_PLUS.t)
          \/ u %% (l' * k * SPHINCS_PLUS.t) %/ (k * SPHINCS_PLUS.t)
             <> v %% (l' * k * SPHINCS_PLUS.t) %/ (k * SPHINCS_PLUS.t)
          \/ u %% (k * SPHINCS_PLUS.t) <> v %% (k * SPHINCS_PLUS.t)
  by smt().
(* Each digit is READ BACK off the address, so a differing digit gives a
   differing index slot, hence distinct addresses. *)
(* The three validity side conditions are LITERALLY rdu/rju/rwu modulo
   unfolding one op each.  `1..3: by smt()` closed them for u and not for v
   under `easycrypt cli` -- which I attributed to smt luck and which was really
   cli's non-iterated smt default (see the correction below).  Named
   introduction rules are kept regardless: supplying the fact beats relying on
   axiom selection to rediscover it, under either driver. *)
have vt : forall (z : int), 0 <= z < nr_trees 0 => valid_tidx 0 z
  by move=> z hz; rewrite /valid_tidx.
have vk : forall (z : int), 0 <= z < l' => valid_kpidx z
  by move=> z hz; rewrite /valid_kpidx.
have vb : forall (z : int), 0 <= z < k * SPHINCS_PLUS.t => valid_tbfidx 0 z
  by move=> z hz; rewrite /valid_tbfidx hnn0.
have gu := tweak_getidx _ _ _ (vt _ rdu) (vk _ rju) (vb _ rwu).
have gv := tweak_getidx _ _ _ (vt _ rdv) (vk _ rjv) (vb _ rwv).
(* GROUNDED CLOSE, no smt.  CORRECTION (2026-08-08): this was originally done
   because the one-liner `[exists 4|exists 2|exists 0]; by rewrite /HA.eq_idx;
   smt()` passed `easycrypt compile` and failed `easycrypt cli`, which I read as
   "a step that closes under one driver's budget is not closed".  THAT READING
   WAS WRONG.  `compile` iterates the smt call by default and `cli` does not;
   the step was closed all along and the comparison was mis-specified.  The
   grounding is kept because it is better anyway -- it depends on two named
   facts instead of on what axiom selection happens to find -- but it fixed no
   defect, and nothing here was ever unsound. *)
have [gu4 [gu2 gu0]] := gu.
have [gv4 [gv2 gv0]] := gv.
rewrite -HA.eq_adrs_idxsq negb_forall /=.
case hone => [hne | [hne | hne]].
+ by exists 4; rewrite /HA.eq_idx gu4 gv4.
+ by exists 2; rewrite /HA.eq_idx gu2 gv2.
by exists 0; rewrite /HA.eq_idx gu0 gv0.
qed.

(* ---------------------------------------------------------------------------
   THE SAMPLING BRIDGE, in isolation.

   This is the step the whole reduction rests on: the game draws a FORS secret
   element as a `dgstblock` (ddgstblock) while the OpenPRE challenger draws its
   hidden preimage as a `dgst` (ddgstblocklift).  If these were not related the
   reduction would be unsound, and no amount of loop-invariant bookkeeping would
   reveal it -- so it is proved here on its own, before being embedded in a
   four-level loop alignment where a failure would be much harder to localise.

   FORS_ES.ec:319 gives ddgstblocklift = dmap ddgstblock DigestBlock.val, so the
   pairing is the bijection (val, insubd).  The four discharges are MM45's
   recipe at FORS_ES.ec:4247-4253: right-cancel, the mu1 transfer via
   in_dmap1E_can, support membership, and left-cancel. *)
module SampGame = {
  proc left() : dgstblock = {
    var e : dgstblock;
    e <$ ddgstblock;
    return e;
  }

  proc right() : dgst = {
    var x : dgst;
    x <$ FTWES.ddgstblocklift;
    return x;
  }
}.

equiv Eqv_sampling_bridge :
  SampGame.left ~ SampGame.right : true ==> DigestBlock.val res{1} = res{2}.
proof.
proc.
rnd DigestBlock.val DigestBlock.insubd.
skip => />.
(* The DigestBlock subtype lemmas need qualifying here; MM45 writes them bare
   because that file imports DigestBlock. *)
split => [x /supp_dmap [x'] [_ ->] | vibij]; 1: by rewrite DigestBlock.valKd.
split => [x /supp_dmap [x'] [xin xval] | eqmu1vi skfele skfelein].
+ by rewrite &(in_dmap1E_can) 1:DigestBlock.insubdK 1:xval 1:DigestBlock.valP
             1,2:// => y _ <-; rewrite DigestBlock.valKd.
split => [| vskfelein]; 1: rewrite supp_dmap; 1: by exists skfele.
by rewrite DigestBlock.valKd.
qed.

(* ==========================================================================
   COVERAGE-LIST LEMMAS for Eqv_OCMA_sign's ENTRY and EXIT.

   Developed standalone in scratch/_entry.ec (~20 s a compile against ~4 min
   here) and folded in verbatim once admit-free.  Same route tws_uniq took.
   ========================================================================== *)


(* ------------------------------------------------------------------------ *)
(* (a) The u-th coverage tuple, CONCRETELY.

   M.F.g is instantiated to FTWES.g (GprocFORSC10.ec:129), which is an explicit
   mkseq, so the abstract `hC` and the loop body's concrete
   `bs2int (rev (take a (drop (a * size sigFORSTW) (val cm))))` are the same
   number -- but only via nth_chunk, which is what this lemma discharges once. *)
(* ------------------------------------------------------------------------ *)
lemma nth_chunk_take_drop (r : int) (s : bool list) (i : int) :
  0 < r => 0 <= i < size s %/ r =>
  nth witness (chunk r s) i = take r (drop (r * i) s).
proof.
move=> hr hi.
by rewrite /chunk nth_mkseq 1:hi.
qed.

lemma hC_nth (mk : mkey) (m : msg) (u : int) :
  0 <= u < k =>
  nth witness (M.F.hC mk m) u
  = (Index.val (FTWES.mco mk m).`2, u,
     bs2int (rev (take a (drop (a * u)
              (FTWES.BLKAL.val (FTWES.mco mk m).`1))))).
proof.
move=> hu.
have ha : 0 < a by smt(ge1_a).
rewrite /M.F.hC /FTWES.g /=.
rewrite nth_mkseq 1:// /=.
congr; congr.
rewrite nth_chunk_take_drop 1:ha 2://.
by rewrite FTWES.BLKAL.valP; smt(ge1_a).
qed.

(* ------------------------------------------------------------------------ *)
(* (b) Every coverage tuple is in range.

   The third component is M.F.rng_g (a realized clone axiom, so a lemma here);
   the first two come straight off the mkseq, the first via the Index subtype
   predicate P i = 0 <= i < l. *)
(* ------------------------------------------------------------------------ *)
lemma hC_range (mk : mkey) (m : msg) (x : int * int * int) :
  x \in M.F.hC mk m =>
  0 <= x.`1 < l /\ 0 <= x.`2 < k /\ 0 <= x.`3 < SPHINCS_PLUS.t.
proof.
move=> hx.
have h3 : 0 <= x.`3 < SPHINCS_PLUS.t by apply (M.F.rng_g (FTWES.mco mk m) x).
move: hx; rewrite /M.F.hC /FTWES.g /= => /mkseqP [i [rng_i hxe]].
by rewrite hxe /=; smt(Index.valP).
qed.

(* ------------------------------------------------------------------------ *)
(* (c) size (hC mk m) = k -- so `drop k (hC mk m) = []` kills the tail
   disjunct at exit. *)
(* ------------------------------------------------------------------------ *)
lemma hC_size (mk : mkey) (m : msg) : size (M.F.hC mk m) = k.
proof. by apply (M.F.size_g (FTWES.mco mk m)). qed.

lemma hC_drop_k (mk : mkey) (m : msg) (n : int) :
  k <= n => drop n (M.F.hC mk m) = [].
proof. by move=> hn; rewrite drop_oversize 1:hC_size. qed.

(* ------------------------------------------------------------------------ *)
(* (d) The ghost target list grows by exactly one message's coverage.  This is
   what keeps `lidxs = flatten (map hC ts)` an invariant across a sign call:
   the left rcons-es `ts`, the right appends `hC mk m`. *)
(* ------------------------------------------------------------------------ *)
lemma flatten_map_hC_rcons (tsl : (mkey * msg) list) (mk : mkey) (m : msg) :
    flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2)
                 (rcons tsl (mk, m)))
  = flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2) tsl)
    ++ M.F.hC mk m.
proof. by rewrite map_rcons flatten_rcons. qed.

(* ------------------------------------------------------------------------ *)
(* (e) The tail shrinks by exactly its head each iteration, and that head is
   the tuple the body opens.  `drop n s = nth .. s n :: drop (n+1) s` is
   drop_nth; membership in the old tail is then "is the head, or is in the new
   tail", which is the step the invariant's disjunct needs. *)
(* ------------------------------------------------------------------------ *)
lemma tail_step (mk : mkey) (m : msg) (n : int) (x : int * int * int) :
  0 <= n < k =>
  (x \in drop n (M.F.hC mk m))
  <=> (x = nth witness (M.F.hC mk m) n \/ x \in drop (n + 1) (M.F.hC mk m)).
proof.
move=> hn.
rewrite (drop_nth witness n) 1:hC_size 1://.
by rewrite in_cons.
qed.

(* ------------------------------------------------------------------------ *)
(* (f) THE FLAT INDEX COLLAPSES TO A TWO-LEVEL MIXED RADIX.

   The challenger indexes images by
     x.`1 %/ l' * l' * k * t + x.`1 %% l' * k * t + x.`2 * t + x.`3,
   which LOOKS like a four-digit encoding needing four range facts to invert.
   It is not: the first two terms recombine by divz_eq into x.`1 * k * t, so
   the whole thing is (x.`1 * k + x.`2) * t + x.`3 -- two levels, and the top
   digit needs NO range hypothesis at all.  That is why flat_inj below asks
   only for the k- and t-digits to be in range.
   Worth the four lines: the four-digit version needs nr_trees/l' bounds and is
   nonlinear enough that smt does not find it. *)
(* ------------------------------------------------------------------------ *)
lemma flat_pack (x : int * int * int) :
    x.`1 %/ l' * l' * k * SPHINCS_PLUS.t + x.`1 %% l' * k * SPHINCS_PLUS.t
    + x.`2 * SPHINCS_PLUS.t + x.`3
  = (x.`1 * k + x.`2) * SPHINCS_PLUS.t + x.`3.
proof.
have h : x.`1 %/ l' * l' + x.`1 %% l' = x.`1 by rewrite -divz_eq.
have -> : x.`1 %/ l' * l' * k * SPHINCS_PLUS.t
          + x.`1 %% l' * k * SPHINCS_PLUS.t
        = (x.`1 %/ l' * l' + x.`1 %% l') * k * SPHINCS_PLUS.t by ring.
by rewrite h; ring.
qed.

(* Injectivity of the flat index on in-range tuples.  Needed exactly ONCE, at
   the loop entry: the incoming coverage biconditional is phrased over TUPLES
   and the invariant over FLAT indices, so the <= direction has to turn
   "some coverage tuple has my flat index" back into "I am that tuple". *)
lemma flat_inj (x y : int * int * int) :
     0 <= x.`2 < k => 0 <= x.`3 < SPHINCS_PLUS.t
  => 0 <= y.`2 < k => 0 <= y.`3 < SPHINCS_PLUS.t
  => (x.`1 * k + x.`2) * SPHINCS_PLUS.t + x.`3
     = (y.`1 * k + y.`2) * SPHINCS_PLUS.t + y.`3
  => x.`1 = y.`1 /\ x.`2 = y.`2 /\ x.`3 = y.`3.
proof.
(* SUPPLY THE INSTANCES.  `rewrite divzMDl 1:ht` does NOT discharge divzMDl's
   `d <> 0`: inside `rewrite`, `n:tac` selects a GOAL, and the side condition
   is not goal 1, so the numbering silently shifted and the failure surfaced two
   rewrites later at divz_small.  Same class as the peel-depth bug in
   Eqv_OCMA_sign's body: guessing a position instead of naming a fact. *)
move=> hx2 hx3 hy2 hy3 heq.
have ht : SPHINCS_PLUS.t <> 0 by smt(ge2_t).
have hk : k <> 0 by smt(ge1_k).
have hxd0 : x.`3 %/ SPHINCS_PLUS.t = 0 by apply divz_small; smt(ge2_t).
have hyd0 : y.`3 %/ SPHINCS_PLUS.t = 0 by apply divz_small; smt(ge2_t).
have hxm0 : x.`3 %% SPHINCS_PLUS.t = x.`3 by apply pmod_small; smt().
have hym0 : y.`3 %% SPHINCS_PLUS.t = y.`3 by apply pmod_small; smt().
(* bottom digit *)
have h3 : x.`3 = y.`3.
+ have e1 := modzMDl (x.`1 * k + x.`2) x.`3 SPHINCS_PLUS.t.
  have e2 := modzMDl (y.`1 * k + y.`2) y.`3 SPHINCS_PLUS.t.
  by rewrite -hxm0 -e1 heq e2 hym0.
(* middle digit *)
have hd : x.`1 * k + x.`2 = y.`1 * k + y.`2.
+ have e1 : ((x.`1 * k + x.`2) * SPHINCS_PLUS.t + x.`3) %/ SPHINCS_PLUS.t
          = x.`1 * k + x.`2
    by rewrite (divzMDl (x.`1 * k + x.`2) x.`3 SPHINCS_PLUS.t ht) hxd0 addr0.
  have e2 : ((y.`1 * k + y.`2) * SPHINCS_PLUS.t + y.`3) %/ SPHINCS_PLUS.t
          = y.`1 * k + y.`2
    by rewrite (divzMDl (y.`1 * k + y.`2) y.`3 SPHINCS_PLUS.t ht) hyd0 addr0.
  by rewrite -e1 heq e2.
have h2 : x.`2 = y.`2.
+ have m1 : x.`2 %% k = x.`2 by apply pmod_small; smt().
  have m2 : y.`2 %% k = y.`2 by apply pmod_small; smt().
  have e1 := modzMDl x.`1 x.`2 k.
  have e2 := modzMDl y.`1 y.`2 k.
  by rewrite -m1 -e1 hd e2 m2.
have h1 : x.`1 = y.`1.
+ have d1 : x.`2 %/ k = 0 by apply divz_small; smt(ge1_k).
  have d2 : y.`2 %/ k = 0 by apply divz_small; smt(ge1_k).
  have f1 : (x.`1 * k + x.`2) %/ k = x.`1
    by rewrite (divzMDl x.`1 x.`2 k hk) d1 addr0.
  have f2 : (y.`1 * k + y.`2) %/ k = y.`1
    by rewrite (divzMDl y.`1 y.`2 k hk) d2 addr0.
  by rewrite -f1 hd f2.
by smt().
qed.


(* Componentwise equality gives tuple equality.  Checked here rather than
   assumed: smt's handling of tuple extensionality is not something to guess
   at inside a four-minute file. *)
lemma tuple3_eq (x y : int * int * int) :
  x.`1 = y.`1 => x.`2 = y.`2 => x.`3 = y.`3 => x = y.
proof. by move: x y => [a b c] [d e f] /= -> -> ->. qed.

(* ------------------------------------------------------------------------ *)
(* (g) THE TWO LIST STEPS the loop invariant's coverage conjunct needs.

   Stated as LIST EQUALITIES, not membership equivalences: `rcons os a ++ L`
   and `os ++ (a :: L)` are literally the same list, so the body's coverage
   step is a rewrite rather than a propositional argument.  That is the payoff
   for phrasing the invariant's disjunct over FLAT indices instead of tuples. *)
(* ------------------------------------------------------------------------ *)
lemma cov_step (osl : int list) (mk : mkey) (m : msg) (n : int) :
  0 <= n < k =>
    osl ++ map (fun (z : int * int * int) =>
                  z.`1 %/ l' * l' * k * SPHINCS_PLUS.t
                  + z.`1 %% l' * k * SPHINCS_PLUS.t
                  + z.`2 * SPHINCS_PLUS.t + z.`3)
               (drop n (M.F.hC mk m))
  = rcons osl ((fun (z : int * int * int) =>
                  z.`1 %/ l' * l' * k * SPHINCS_PLUS.t
                  + z.`1 %% l' * k * SPHINCS_PLUS.t
                  + z.`2 * SPHINCS_PLUS.t + z.`3)
                 (nth witness (M.F.hC mk m) n))
    ++ map (fun (z : int * int * int) =>
              z.`1 %/ l' * l' * k * SPHINCS_PLUS.t
              + z.`1 %% l' * k * SPHINCS_PLUS.t
              + z.`2 * SPHINCS_PLUS.t + z.`3)
           (drop (n + 1) (M.F.hC mk m)).
proof.
move=> hn.
rewrite (drop_nth witness n) 1:hC_size 1:hn.
by rewrite map_cons -cats1 -catA cat1s.
qed.

lemma cov_exit (osl : int list) (mk : mkey) (m : msg) (n : int) :
  k <= n =>
    osl ++ map (fun (z : int * int * int) =>
                  z.`1 %/ l' * l' * k * SPHINCS_PLUS.t
                  + z.`1 %% l' * k * SPHINCS_PLUS.t
                  + z.`2 * SPHINCS_PLUS.t + z.`3)
               (drop n (M.F.hC mk m))
  = osl.
proof. by move=> hn; rewrite hC_drop_k 1:hn /= cats0. qed.

(* ------------------------------------------------------------------------ *)
(* (h) THE TWO FACTS THE WIN CONDITION OPENS WITH.

   The reduction picks its OpenPRE target as
     E = nth witness (hC mk' m') (find (fun x => ! (x \in cov)) (hC mk' m'))
   and then indexes the challenge list at
     E.`1 %/ l' * l'*k*t + E.`1 %% l' * k*t + E.`2 * t + E.`3.
   Two things have to be true before any of that means anything: the find must
   SUCCEED (which is exactly what `!covered` gives), and E.`1 must be the
   message's own tree index (which is what makes the flat index land in the
   right instance). *)
(* ------------------------------------------------------------------------ *)
lemma hC_fst (mk : mkey) (m : msg) (x : int * int * int) :
  x \in M.F.hC mk m => x.`1 = Index.val (FTWES.mco mk m).`2.
proof.
by rewrite /M.F.hC /FTWES.g /= => /mkseqP [i [rng_i ->]].
qed.

(* `!covered` IS "the find succeeds".  covered is `all (mem cov) (hC mk' m')`,
   so its negation is `has (predC (mem cov))`, and has_find/nth_find turn that
   into a real index with a real witness. *)
lemma find_fresh (c : (int * int * int) list) (hh : (int * int * int) list) :
  ! all (fun (x : int * int * int) => x \in c) hh =>
     0 <= find (fun (x : int * int * int) => ! (x \in c)) hh < size hh
  /\ nth witness hh (find (fun (x : int * int * int) => ! (x \in c)) hh) \in hh
  /\ ! (nth witness hh
          (find (fun (x : int * int * int) => ! (x \in c)) hh) \in c).
proof.
move=> hna.
have hs : has (fun (x : int * int * int) => ! (x \in c)) hh
  (* DETERMINISTIC, was `by smt(allP hasP)` (2026-08-20).  That smt call discharged the
     all/has duality BY SEARCH and was MARGINAL at the toolchain's default prover budget:
     7/10 passes measured (2 failures across 7 full-gate runs, 1 in 3 in isolation with
     the gate's exact flags).  A flaky proof makes every receipt containing it a
     measurement of machine speed rather than of the proof -- the same defect this repo
     already fixed once for EncoderBridge.pow8.  `has_predC` (List.ec:568) states exactly
     this duality, so the step is now a named rewrite with no search at all.
     Negative control run before adopting it: with the hypothesis `hna` deleted the same
     tactic FAILS ("cannot close goals"), so it is genuinely using it. *)
  by rewrite -/(predC _) has_predC.
have hlt : find (fun (x : int * int * int) => ! (x \in c)) hh < size hh
  by rewrite -has_find.
have hge : 0 <= find (fun (x : int * int * int) => ! (x \in c)) hh
  by apply find_ge0.
have hin : nth witness hh
             (find (fun (x : int * int * int) => ! (x \in c)) hh) \in hh
  by apply mem_nth; smt().
have hp := nth_find witness (fun (x : int * int * int) => ! (x \in c)) hh hs.
smt().
qed.

(* ==========================================================================
   THE WIN CONDITION (T1-T5), AS A STANDALONE PURE LEMMA.

   WHY IT IS NOT WRITTEN INLINE.  Inside t1_opre_bound the five targets sit
   under a pRHL `skip` whose every subterm is a memory-qualified global, and
   one iteration there costs ~4-5 min.  Stated over plain values it costs 14 s,
   and the pRHL side then reduces to a single `apply` with the hypotheses it
   already has by framing.  Same route the coverage-list lemmas took.

   `E` is a parameter with a DEFINING hypothesis rather than the spelled-out
   `nth .. (find ..)` term, purely so the statement is readable; the caller
   never supplies it -- unification against the goal does.

   NOTHING HERE USES `is_valid` OR `is_fresh`.  All five targets follow from
   `!covered` (via hna) and `valid_OpenPRE` (hvop) alone, which is what lets
   the pkFORS_from_sigFORSTW call be discharged losslessly.

   THE MUST-FAIL CONTROLS, recorded as a recipe rather than as two more 1600-line
   copies of this file.  Take this file, replace ONE premise of t1_win with
   `true`, compile, and check WHERE it fails -- exit status alone grades nothing:
     - drop `! all (mem lidxsL) (M.F.hC mk' m')`  -> must fail at find_fresh's
       premise (`[by]: cannot close goals` at the `have [_ [hEin hEni]]` line),
       i.e. `!covered` is what makes the find succeed;
     - drop `size twsL = nr_trees 0 * l' * k * t` -> must fail at T4's
       `rewrite size_map hszts hsztws` (`nothing to rewrite`).
   Both were run 2026-08-10 and failed exactly there.

   SCOPE OF "ADMIT-FREE", stated because the phrase is easy to over-read and I
   over-read it myself before checking.  THIS FILE is admit=0/axiom=0/sorry=0,
   and so is every cdrafts file t1_win cites (GprocVI, FxChain, GprocFORSC10).
   The full require-cone of this file is NOT admit-free: a census of all 25 cone
   files (tools/cert_cone.py + scratch/sweep.py, the gate's own tools) shows
     base-c10-split/WOTS_TW_ES.ec  admit=1  axiom=5
   plus recorded axiom rows in FORS_ES (3), SPHINCS_PLUS (8), FL_SL (2),
   OpenPRE_From_TCR_DSPR_THF (2), TweakableHashFunctions (1), FORS_C10 (7),
   STCR_C (1).  That admit is a PRE-EXISTING, BASELINE-PINNED item --
   cert-baseline-split.tsv carries the row `admit:aac0bca56296` for
   WOTS_TW_ES.ec, and PHASE 2 treats additions as fatal -- so it is inherited
   from MM45's vendored base and is shared by T2, T3 and the whole certified
   artifact alike.  It is NOT something this proof introduced, and it is NOT a
   T1-specific caveat; but "T1 is admit-free" is a statement about the BRANCH
   PROOF, not about its cone, and should not be repeated without that scope. *)
lemma t1_win (tsL : (adrs * dgstblock) list) (xsL : dgst list)
             (twsL : adrs list) (osL : int list)
             (lidxsL : (int * int * int) list) (ppv : pseed)
             (skFnt : FTWES.skFORS list list) (mk' : mkey) (m' : msg)
             (apkl : (dgstblock * FTWES.apFORSTW) list)
             (E : int * int * int) :
     size tsL = nr_trees 0 * l' * k * SPHINCS_PLUS.t
  => size twsL = nr_trees 0 * l' * k * SPHINCS_PLUS.t
  => (forall (i j w : int),
        0 <= i < nr_trees 0 => 0 <= j < l' => 0 <= w < k * SPHINCS_PLUS.t =>
        nth witness twsL
          (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t + w)
        = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 w)
  => (forall (idx0 : int), 0 <= idx0 < size tsL =>
        nth witness tsL idx0
        = (nth witness twsL idx0,
           f ppv (nth witness twsL idx0) (nth witness xsL idx0)))
  => (forall (i j u v : int),
        0 <= i < nr_trees 0 => 0 <= j < l' => 0 <= u < k =>
        0 <= v < SPHINCS_PLUS.t =>
        nth witness xsL (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                         + u * SPHINCS_PLUS.t + v)
        = DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val
            (nth witness (nth witness skFnt i) j)) u) v))
  => (forall (idxs : int * int * int),
        idxs \in lidxsL
        <=> (0 <= idxs.`1 < l /\ 0 <= idxs.`2 < k
             /\ 0 <= idxs.`3 < SPHINCS_PLUS.t
             /\ idxs.`1 %/ l' * l' * k * SPHINCS_PLUS.t
                + idxs.`1 %% l' * k * SPHINCS_PLUS.t
                + idxs.`2 * SPHINCS_PLUS.t + idxs.`3 \in osL))
  => ! all (mem lidxsL) (M.F.hC mk' m')
  => f ppv
       (set_thtbidx
          (set_kpidx (set_tidx (set_typeidx adz trhftype) (E.`1 %/ l'))
             (E.`1 %% l')) 0 (E.`2 * SPHINCS_PLUS.t + E.`3))
       (DigestBlock.val (nth witness apkl E.`2).`1)
     = nth witness
         (fors_leaves_op_cube
            (nth witness (nth witness skFnt (E.`1 %/ l')) (E.`1 %% l'))
            ppv
            (set_kpidx (set_tidx (set_typeidx adz trhftype) (E.`1 %/ l'))
               (E.`1 %% l'))
            E.`2)
         E.`3
  => E = nth witness (M.F.hC mk' m')
           (find (fun (i3 : int * int * int) => ! (i3 \in lidxsL))
              (M.F.hC mk' m'))
  =>    0 <= Index.val (FTWES.mco mk' m').`2 %/ l' * l' * k * SPHINCS_PLUS.t
             + Index.val (FTWES.mco mk' m').`2 %% l' * k * SPHINCS_PLUS.t
             + E.`2 * SPHINCS_PLUS.t + E.`3
        < size tsL
     /\ 0 <= size tsL <= l * k * SPHINCS_PLUS.t
     /\ ! (Index.val (FTWES.mco mk' m').`2 %/ l' * l' * k * SPHINCS_PLUS.t
           + Index.val (FTWES.mco mk' m').`2 %% l' * k * SPHINCS_PLUS.t
           + E.`2 * SPHINCS_PLUS.t + E.`3 \in osL)
     /\ uniq (unzip1 tsL)
     /\ f ppv
          (nth witness tsL
             (Index.val (FTWES.mco mk' m').`2 %/ l' * l' * k * SPHINCS_PLUS.t
              + Index.val (FTWES.mco mk' m').`2 %% l' * k * SPHINCS_PLUS.t
              + E.`2 * SPHINCS_PLUS.t + E.`3)).`1
          (DigestBlock.val (nth witness apkl E.`2).`1)
        = (nth witness tsL
             (Index.val (FTWES.mco mk' m').`2 %/ l' * l' * k * SPHINCS_PLUS.t
              + Index.val (FTWES.mco mk' m').`2 %% l' * k * SPHINCS_PLUS.t
              + E.`2 * SPHINCS_PLUS.t + E.`3)).`2.
proof.
move=> hszts hsztws htwsc htsc hxsc hCOV hna hvop hEdef.
(* THE FIND SUCCEEDS.  `!covered` is exactly "some tuple of hC mk' m' is not in
   the coverage list", so find returns a real index with a real witness. *)
have [_ [hEin hEni]] := find_fresh lidxsL (M.F.hC mk' m') _;
  first by move: hna; rewrite !allP /=.
rewrite -hEdef in hEin.
rewrite -hEdef in hEni.
have hrng := hC_range mk' m' E hEin.
have hfst := hC_fst mk' m' E hEin.
have hi := edivz_tidx_bound ((FTWES.mco mk' m').`2).
have hj := edivz_kpidx_bound ((FTWES.mco mk' m').`2).
(* T1, ESTABLISHED AND NAMED BEFORE THE SPLIT.  T5 needs it as htsc's side
   condition, and proving it inside the T1 branch would not put it in scope
   there. *)
have hcidx :
     0 <= Index.val (FTWES.mco mk' m').`2 %/ l' * l' * k * SPHINCS_PLUS.t
          + Index.val (FTWES.mco mk' m').`2 %% l' * k * SPHINCS_PLUS.t
          + E.`2 * SPHINCS_PLUS.t + E.`3
     < size tsL.
+ have hge0 := flat_idx_ge0 (Index.val (FTWES.mco mk' m').`2 %/ l')
                            (Index.val (FTWES.mco mk' m').`2 %% l')
                            E.`2 E.`3 _ _ _ _; 1..4: by smt().
  have hlt := flat_idx_lt (Index.val (FTWES.mco mk' m').`2 %/ l')
                          (Index.val (FTWES.mco mk' m').`2 %% l')
                          E.`2 E.`3 (nr_trees 0) 0 0 0 _ _ _ _ _ _ _;
    1..7: by smt().
  by rewrite hszts; smt().
split; first by exact hcidx.
(* T2.  size ts = nr_trees 0 * l' * k * t and nr_trees 0 * l' = l, so the
   bound is an EQUALITY; the lower half is size_ge0, not arithmetic. *)
have hl : size tsL = l * k * SPHINCS_PLUS.t by rewrite hszts -nr_trees0_l.
have hge := size_ge0 tsL.
split; first by rewrite hl; smt().
(* T3.  THE COVERAGE BICONDITIONAL, which is what the invariant strengthening
   existed for: E is not in lidxs, the ranges hold, so its flat index is not
   in os. *)
have hb := hCOV E.
split.
+ rewrite -hfst.
  smt().
(* T4.  unzip1 ts = tws pointwise, then tws_uniq. *)
have huz : unzip1 tsL = twsL.
+ apply (eq_from_nth witness); first by rewrite size_map hszts hsztws.
  move=> i0 hi0; rewrite size_map in hi0.
  rewrite (nth_map witness witness); first by exact hi0.
  rewrite htsc; first by exact hi0.
  by simplify.
split; first by rewrite huz; apply (tws_uniq twsL hsztws htwsc).
(* T5.  NO INJECTIVITY OF f IS NEEDED, and that is the whole point: the target
   value is f pp tw xs[cidx], the forgery value is f pp tw x', and hvop says
   those two are equal.  What has to be shown is only that the tweak and the
   secret element the LEFT side names are the ones ts[cidx] is built from. *)
have hnm : forall (g : int -> dgstblock),
  nth witness (mkseq g SPHINCS_PLUS.t) E.`3 = g E.`3.
+ by move=> g; apply (nth_mkseq witness); smt().
have hlf := hvop.
rewrite hfst cube_is_mkseq hnm /= in hlf.
have htw : nth witness twsL
             (Index.val (FTWES.mco mk' m').`2 %/ l' * l' * k * SPHINCS_PLUS.t
              + Index.val (FTWES.mco mk' m').`2 %% l' * k * SPHINCS_PLUS.t
              + E.`2 * SPHINCS_PLUS.t + E.`3)
         = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
             (Index.val (FTWES.mco mk' m').`2 %/ l'))
             (Index.val (FTWES.mco mk' m').`2 %% l')) 0
             (E.`2 * SPHINCS_PLUS.t + E.`3).
+ have -> : Index.val (FTWES.mco mk' m').`2 %/ l' * l' * k * SPHINCS_PLUS.t
            + Index.val (FTWES.mco mk' m').`2 %% l' * k * SPHINCS_PLUS.t
            + E.`2 * SPHINCS_PLUS.t + E.`3
          = Index.val (FTWES.mco mk' m').`2 %/ l' * l' * k * SPHINCS_PLUS.t
            + Index.val (FTWES.mco mk' m').`2 %% l' * k * SPHINCS_PLUS.t
            + (E.`2 * SPHINCS_PLUS.t + E.`3) by ring.
  (* Use the existing flat-index bound directly: SMT search in this context
     can exhaust its per-call budget when proof workers run concurrently. *)
  have [_ [[hu0 huk] [hv0 hvt]]] := hrng.
  have ht0 : 0 <= SPHINCS_PLUS.t by apply (ler_trans 2 _ _ _ ge2_t).
  have hv1 : E.`3 <= SPHINCS_PLUS.t - 1 by rewrite ler_subr_addr -ltzE.
  have hub := flat_le SPHINCS_PLUS.t E.`2 k E.`3 ht0 hu0 huk hv0 hv1.
  have hw : 0 <= E.`2 * SPHINCS_PLUS.t + E.`3 < k * SPHINCS_PLUS.t.
  + split; first exact (addr_ge0 _ _ (mulr_ge0 _ _ hu0 ht0) hv0).
    by rewrite ltzE -ler_subr_addr.
  by apply (htwsc _ _ _ hi hj hw).
have hxs : nth witness xsL
             (Index.val (FTWES.mco mk' m').`2 %/ l' * l' * k * SPHINCS_PLUS.t
              + Index.val (FTWES.mco mk' m').`2 %% l' * k * SPHINCS_PLUS.t
              + E.`2 * SPHINCS_PLUS.t + E.`3)
         = DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val
             (nth witness (nth witness skFnt
                (Index.val (FTWES.mco mk' m').`2 %/ l'))
                (Index.val (FTWES.mco mk' m').`2 %% l'))) E.`2) E.`3).
+ by apply hxsc; smt().
rewrite htsc; first by exact hcidx.
rewrite /= htw hxs.
by apply hlf.
qed.



(* THE ORACLE EQUIVALENCE, STATED.  Same discipline as t1_opre_bound below:
   stating it is what checks that the invariant TYPECHECKS against both oracles
   -- every global it names must exist on the side it names it on, with the
   right type -- and that is the last plumbing that can be wrong for free.
   The proof is deferred, so this file reports one more admit than the bound
   alone; cert-watched-split.tsv is updated in the same commit.

   It is stated over the globals only: tidx/kpidx/sig/ad0/skFORS0 are locals of
   the two sign bodies and belong to the loop invariant, not here.

   THE C10 DELTA, restated where it bites.  MM45's invariant (FORS_ES.ec:4525)
   carries `={mmap}`, `dom mmap = mem qs`, and an all-covered condition over
   `g (mco (oget mmap.[m]) m)`.  Gproc's O_CMA_Gproc_I does NOT memoise, so all
   three collapse into the single equation
     lidxs{2} = flatten (map (fun km => hC km.`1 km.`2) O_CMA_Gproc_I.ts{1}),
   which is STRONGER (an equality, not an inclusion) and is exactly
   EUF_CMA_Gproc_V's ghost `cov` -- so it is also what will tie `!covered` to
   the freshness of the chosen index.

   The load-bearing member is the last one: lidxs <-> os.  It is what makes
   `!opened` provable at the end, and it is the reason os{2} = [] is carried
   INTO the forge call but is NOT preserved by it -- every O.open appends. *)
lemma Eqv_OCMA_sign
  (A <: Adv_EUFCMA_Gproc{-O_CMA_Gproc_I, -R_OPRE_Gproc,
                         -FTWES.F_OpenPRE.O_SMDTOpenPRE_Default}) :
  equiv[ O_CMA_Gproc_I.sign
         ~ R_OPRE_Gproc(A, FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).O_CMA.sign :
           ={arg}
        /\ O_CMA_Gproc_I.ps{1} = R_OPRE_Gproc.ps{2}
        /\ O_CMA_Gproc_I.ad{1} = adz
        /\ R_OPRE_Gproc.ad{2} = adz
        /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = R_OPRE_Gproc.ps{2}
        /\ R_OPRE_Gproc.lidxs{2}
           = flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2)
                          O_CMA_Gproc_I.ts{1})
        /\ (forall (i j u v : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
              0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
              nth witness R_OPRE_Gproc.leavess{2}
                (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                 + u * SPHINCS_PLUS.t + v)
              = f FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2}
                  (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
                     0 (u * SPHINCS_PLUS.t + v))
                  (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                    (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                     + u * SPHINCS_PLUS.t + v)))
        /\ (forall (i j u v : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
              0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
              nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                 + u * SPHINCS_PLUS.t + v)
              = DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val
                  (nth witness (nth witness O_CMA_Gproc_I.sks{1} i) j)) u) v))
        /\ (forall (idxs : int * int * int),
              idxs \in R_OPRE_Gproc.lidxs{2}
              <=> (0 <= idxs.`1 < l /\ 0 <= idxs.`2 < k
                   /\ 0 <= idxs.`3 < SPHINCS_PLUS.t
                   /\ idxs.`1 %/ l' * l' * k * SPHINCS_PLUS.t
                      + idxs.`1 %% l' * k * SPHINCS_PLUS.t
                      + idxs.`2 * SPHINCS_PLUS.t + idxs.`3
                      \in FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2}))
        /\ size R_OPRE_Gproc.leavess{2}
           = nr_trees 0 * l' * k * SPHINCS_PLUS.t
        ==>    ={res}
        /\ O_CMA_Gproc_I.ps{1} = R_OPRE_Gproc.ps{2}
        /\ O_CMA_Gproc_I.ad{1} = adz
        /\ R_OPRE_Gproc.ad{2} = adz
        /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = R_OPRE_Gproc.ps{2}
        /\ R_OPRE_Gproc.lidxs{2}
           = flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2)
                          O_CMA_Gproc_I.ts{1})
        (* THE POST MUST RESTATE THE PRE, conjunct for conjunct.  `call (: I)`
           against an abstract adversary needs the oracle equiv in the shape
           `={arg} /\ I ==> ={res} /\ I`; a post that DROPS a conjunct the pre
           carries is not that shape, and the forge call cannot use it.  These
           two were dropped in the first version because the loop body is what
           consumes them -- but the sign call touches neither leavess, xs nor
           sks, so they survive it and must say so. *)
        /\ (forall (i j u v : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
              0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
              nth witness R_OPRE_Gproc.leavess{2}
                (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                 + u * SPHINCS_PLUS.t + v)
              = f FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2}
                  (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
                     0 (u * SPHINCS_PLUS.t + v))
                  (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                    (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                     + u * SPHINCS_PLUS.t + v)))
        /\ (forall (i j u v : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
              0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
              nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                 + u * SPHINCS_PLUS.t + v)
              = DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val
                  (nth witness (nth witness O_CMA_Gproc_I.sks{1} i) j)) u) v))
        /\ (forall (idxs : int * int * int),
              idxs \in R_OPRE_Gproc.lidxs{2}
              <=> (0 <= idxs.`1 < l /\ 0 <= idxs.`2 < k
                   /\ 0 <= idxs.`3 < SPHINCS_PLUS.t
                   /\ idxs.`1 %/ l' * l' * k * SPHINCS_PLUS.t
                      + idxs.`1 %% l' * k * SPHINCS_PLUS.t
                      + idxs.`2 * SPHINCS_PLUS.t + idxs.`3
                      \in FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2}))
        /\ size R_OPRE_Gproc.leavess{2}
           = nr_trees 0 * l' * k * SPHINCS_PLUS.t ].
proof.
proc.
(* The left's sign call.  Names below are READ OFF the post-inline goal, not
   carried over from MM45: their inlined pseed/adrs locals are ps0/ad0 because
   theirs collide, ours are plain `ps`/`ad` because O_CMA_Gproc_I.ps and .ad are
   module GLOBALS and so do not collide with the inlined locals.  Only skFORS0
   and m0 are actually renamed.  Guessing this cost one compile. *)
inline{1} 6.
wp => /=.
(* ONE loop, not two: MM45 splits on the mmap miss/hit test, and Gproc has no
   mmap, so their `if => //` and its duplicated loop both vanish. *)
while (   ={tidx, kpidx}
       /\ sig{1} = sigFORSTW{2}
       /\ m0{1} = cm{2}
       /\ ps{1} = R_OPRE_Gproc.ps{2}
       /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = R_OPRE_Gproc.ps{2}
       /\ R_OPRE_Gproc.ad{2} = adz
       /\ ad{1} = set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{2}) kpidx{2}
       /\ skFORS0{1}
          = nth witness (nth witness O_CMA_Gproc_I.sks{1} tidx{2}) kpidx{2}
       /\ (forall (i j u v : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
             0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
             nth witness R_OPRE_Gproc.leavess{2}
               (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                + u * SPHINCS_PLUS.t + v)
             = f FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2}
                 (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
                    0 (u * SPHINCS_PLUS.t + v))
                 (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                   (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                    + u * SPHINCS_PLUS.t + v)))
       /\ (forall (i j u v : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
             0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
             nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
               (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                + u * SPHINCS_PLUS.t + v)
             = DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val
                 (nth witness (nth witness O_CMA_Gproc_I.sks{1} i) j)) u) v))
       /\ size R_OPRE_Gproc.leavess{2}
          = nr_trees 0 * l' * k * SPHINCS_PLUS.t
       /\ size sigFORSTW{2} <= k
       (* The tree/keypair bounds.  NOT decoration: the leaves and xs
          characterisations are quantified with exactly these ranges as
          premises, so without them in the invariant the body's instance at
          (tidx,kpidx) is not derivable at all -- which is what the first
          attempt at this discharge ran into.  They are proof-internal, so the
          pinned Eqv_OCMA_sign digest does not move.  The body preserves them
          trivially (it writes neither counter); the entry gets them from
          edivz_{tidx,kpidx}_bound. *)
       /\ 0 <= tidx{2} < nr_trees 0
       /\ 0 <= kpidx{2} < l'
       (* ------------------------------------------------------------------
          THE COVERAGE BOOKKEEPING.  Everything below is here because the EXIT
          needs it, and a cli dump is what showed that: the exit obligation
          reads `forall sig_L os_R sigFORSTW_R, ... => <post mentioning os_R>`,
          so any conjunct of the post naming `os`, `lidxs` or a global the loop
          does not touch must still be carried, or the goal is not merely hard
          but UNPROVABLE -- its conclusion constrains variables its hypotheses
          never mention.  That is the whole reason this block exists.
          ------------------------------------------------------------------ *)
       (* Globals the post re-asserts.  `while` forgets whatever the invariant
          does not name, including things the loop provably cannot touch. *)
       /\ ={mk}
       /\ O_CMA_Gproc_I.ps{1} = R_OPRE_Gproc.ps{2}
       /\ O_CMA_Gproc_I.ad{1} = adz
       /\ R_OPRE_Gproc.lidxs{2}
          = flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2)
                         O_CMA_Gproc_I.ts{1})
       (* Tie cm/idx/tidx/kpidx back to (mk, m), so the body can identify the
          index it opens with the u-th coverage tuple (hC_nth). *)
       /\ cm{2} = (FTWES.mco mk{2} m{2}).`1
       /\ idx{2} = (FTWES.mco mk{2} m{2}).`2
       /\ tidx{2} = Index.val idx{2} %/ l'
       /\ kpidx{2} = Index.val idx{2} %% l'
       (* THE lidxs <-> os RELATION, mid-loop.  `lidxs <- lidxs ++ hC mk m`
          already ran, so lidxs holds all k tuples while os holds only the
          opened prefix: the PLAIN biconditional is false here.  The tail
          `drop (size sigFORSTW) (hC mk m)` is exactly the not-yet-opened part,
          and phrasing the disjunct over FLAT indices (rather than tuples) is
          what makes the body step pure list algebra -- `rcons os a ++ L` and
          `os ++ (a :: L)` are the SAME list -- and confines the injectivity
          argument to the entry, where it is needed once. *)
       /\ (forall (idxs : int * int * int),
             idxs \in R_OPRE_Gproc.lidxs{2}
             <=> (0 <= idxs.`1 < l /\ 0 <= idxs.`2 < k
                  /\ 0 <= idxs.`3 < SPHINCS_PLUS.t
                  /\ (idxs.`1 %/ l' * l' * k * SPHINCS_PLUS.t
                      + idxs.`1 %% l' * k * SPHINCS_PLUS.t
                      + idxs.`2 * SPHINCS_PLUS.t + idxs.`3)
                     \in FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2}
                         ++ map (fun (z : int * int * int) =>
                                   z.`1 %/ l' * l' * k * SPHINCS_PLUS.t
                                   + z.`1 %% l' * k * SPHINCS_PLUS.t
                                   + z.`2 * SPHINCS_PLUS.t + z.`3)
                                (drop (size sigFORSTW{2})
                                      (M.F.hC mk{2} m{2}))))).
+ (* BODY.  Left 1-3 and right 1-3 are assignments; left 4 is the leaves call,
     right 4 is O.open.  Inline the open, wp both tails, then discharge the
     left's call against the certified leaves characterisation.
     exists* is safe here, unlike in the pk body where it captured a stale
     value: none of left 1-3 writes sig, skFORS0, ps or ad.
     THE CALL NEEDS A PHOARE, NOT A HOARE.  A one-sided call{1} must be
     lossless, which is why genpkfors_cf_op (already a phoare) dropped straight
     in and this one does not: FxChain certifies the leaves characterisation
     SPLIT -- genleaves_cube_cf_h is the hoare, genleaves_cube_ll the
     losslessness -- so they are combined here with conseq first.  FxChain uses
     the same idiom internally at :805 and :847. *)
  inline{2} 4.
  wp => /=.
  exists* (size sig{1}), skFORS0{1}, ps{1}, ad{1}.
  elim* => szv skFv psv advv.
  have Hp : phoare[FTWES.FL_FORS_ES_NPRF.gen_leaves_single_tree :
                     idxt = szv /\ skFORS = skFv /\ ps = psv /\ ad = advv
                     ==> res = fors_leaves_op_cube skFv psv advv szv] = 1%r
    by conseq genleaves_cube_ll (genleaves_cube_cf_h szv skFv psv advv).
  call{1} Hp.
  wp; skip => &1 &2 hpre.
  (* PEEL AND NAME, depth READ OFF a cli dump of this very goal rather than
     counted by eye.  The first attempt at this discharge left the conjuncts
     anonymous inside `hpre` and asked smt to find a four-way instantiation
     buried in a twelve-way conjunction; it did not, and expanding the address
     -- the only part I had guessed at -- moved nothing, because the address was
     never what was missing.  Same lesson as tws_uniq: supply the instance. *)
  move: hpre => [[hszv [hskFv [hpsv hadvv]]]
                 [[[htidx hkpidx]
                   [hsig [hm0 [hps [hpp [had2 [hadL [hskF
                     [hlvinv [hxsinv [hszlv [hszsig
                       [htb [hkb [hmk [hgps [hgad [hlid
                         [hcm [hidxe [htidxe [hkpidxe hcov]]]]]]]]]]]]]]]]]]]]]]
                  [hltL hltR]]].
  (* `&&` is EasyCrypt's ASYMMETRIC and: split yields `A` and `A => B`, so the
     second branch carries one extra intro.  Getting this wrong shifts every
     later intro by one and surfaces two tactics downstream. *)
  split; first by rewrite /= hszv hskFv hpsv hadvv.
  move=> _ result hres.
  (* The per-tree message index lands in [0,t) -- FxChain:606. *)
  have hidx : 0 <= bs2int (rev (take a (drop (a * size sigFORSTW{2})
                                          (FTWES.BLKAL.val cm{2}))))
              < SPHINCS_PLUS.t
    by apply (fors_lfidx_bound cm{2} (size sigFORSTW{2})); smt(size_ge0).
  (* The two characterisations, GROUNDED at (tidx,kpidx,size sigFORSTW,-). *)
  have hchar : forall (v : int), 0 <= v < SPHINCS_PLUS.t =>
      nth witness R_OPRE_Gproc.leavess{2}
        (tidx{2} * l' * k * SPHINCS_PLUS.t + kpidx{2} * k * SPHINCS_PLUS.t
         + size sigFORSTW{2} * SPHINCS_PLUS.t + v)
      = f FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2}
          (set_thtbidx
             (set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{2}) kpidx{2})
             0 (size sigFORSTW{2} * SPHINCS_PLUS.t + v))
          (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
            (tidx{2} * l' * k * SPHINCS_PLUS.t + kpidx{2} * k * SPHINCS_PLUS.t
             + size sigFORSTW{2} * SPHINCS_PLUS.t + v)).
  + move=> v hv.
    by apply (hlvinv tidx{2} kpidx{2} (size sigFORSTW{2}) v); smt(size_ge0).
  have hxse : forall (v : int), 0 <= v < SPHINCS_PLUS.t =>
      nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
        (tidx{2} * l' * k * SPHINCS_PLUS.t + kpidx{2} * k * SPHINCS_PLUS.t
         + size sigFORSTW{2} * SPHINCS_PLUS.t + v)
      = DigestBlock.val
          (nth witness (nth witness (FTWES.DBLLKTL.val skFORS0{1})
                          (size sigFORSTW{2})) v).
  + move=> v hv.
    rewrite hskF.
    by apply (hxsinv tidx{2} kpidx{2} (size sigFORSTW{2}) v); smt(size_ge0).
  (* The cube fits.  Three flat_span telescopes, innermost first: each one's
     `lo <= W` premise is the previous one's conclusion. *)
  have hb0 : 0 <= tidx{2} * l' * k * SPHINCS_PLUS.t
                 + kpidx{2} * k * SPHINCS_PLUS.t
    by smt(mulr_ge0 FTWES.ge1_l ge1_k ge2_t).
  have hfit : tidx{2} * l' * k * SPHINCS_PLUS.t + kpidx{2} * k * SPHINCS_PLUS.t
              + size sigFORSTW{2} * SPHINCS_PLUS.t + SPHINCS_PLUS.t
              <= size R_OPRE_Gproc.leavess{2}.
  + rewrite hszlv.
    have s3 := flat_span SPHINCS_PLUS.t (size sigFORSTW{2}) k SPHINCS_PLUS.t
                 _ _ _ _; 1..4: by smt(ge2_t size_ge0).
    have s2 := flat_span (k * SPHINCS_PLUS.t) kpidx{2} l'
                 (size sigFORSTW{2} * SPHINCS_PLUS.t + SPHINCS_PLUS.t)
                 _ _ _ _; 1..4: by smt(ge1_k ge2_t size_ge0).
    have s1 := flat_span (l' * k * SPHINCS_PLUS.t) tidx{2} (nr_trees 0)
                 (kpidx{2} * k * SPHINCS_PLUS.t
                  + size sigFORSTW{2} * SPHINCS_PLUS.t + SPHINCS_PLUS.t)
                 _ _ _ _; 1..4: by smt(FTWES.ge1_l ge1_k ge2_t size_ge0).
    smt().
  (* THE CUBE.  This is the whole point of the body: the left's freshly
     generated leaf cube IS the corresponding window of the challenger's
     image list. *)
  have hlv := leaves_eq_cube_char R_OPRE_Gproc.leavess{2}
                FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2}
                (set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{2}) kpidx{2})
                skFORS0{1}
                (tidx{2} * l' * k * SPHINCS_PLUS.t
                 + kpidx{2} * k * SPHINCS_PLUS.t)
                (size sigFORSTW{2}) _ _ _ hchar hxse; 1..3: by smt(size_ge0).
  rewrite hpp in hlv.
  have hresult : result
    = take SPHINCS_PLUS.t
        (drop (tidx{2} * l' * k * SPHINCS_PLUS.t
               + kpidx{2} * k * SPHINCS_PLUS.t
               + size sigFORSTW{2} * SPHINCS_PLUS.t) R_OPRE_Gproc.leavess{2})
    by rewrite hres hszv hskFv hpsv hadvv hsig hadL hps -hlv.
  (* The signed element: the challenger's preimage at the same flat index,
     lifted back through the subtype. *)
  have hele :
      nth witness (nth witness (FTWES.DBLLKTL.val skFORS0{1})
                     (size sigFORSTW{2}))
        (bs2int (rev (take a (drop (a * size sigFORSTW{2})
                                (FTWES.BLKAL.val cm{2})))))
    = DigestBlock.insubd
        (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
          (tidx{2} * l' * k * SPHINCS_PLUS.t + kpidx{2} * k * SPHINCS_PLUS.t
           + size sigFORSTW{2} * SPHINCS_PLUS.t
           + bs2int (rev (take a (drop (a * size sigFORSTW{2})
                                    (FTWES.BLKAL.val cm{2})))))).
  + rewrite (hxse (bs2int (rev (take a (drop (a * size sigFORSTW{2})
                                          (FTWES.BLKAL.val cm{2}))))) hidx).
    by rewrite DigestBlock.valKd.
  (* Restore the invariant, conjunct by conjunct.  The guard equivalence goes
     first because `last` is cheaper than counting splits to it. *)
  split; last by rewrite !size_rcons hsig.
  split; first by rewrite htidx hkpidx.
  split; first by rewrite hsig hm0; congr;
                  rewrite hresult hele hadL hps had2.
  split; first by exact hm0.
  split; first by exact hps.
  split; first by exact hpp.
  split; first by exact had2.
  split; first by exact hadL.
  split; first by exact hskF.
  split; first by exact hlvinv.
  split; first by exact hxsinv.
  split; first by exact hszlv.
  split; first by rewrite size_rcons; smt().
  split; first by exact htb.
  split; first by exact hkb.
  split; first by exact hmk.
  split; first by exact hgps.
  split; first by exact hgad.
  split; first by exact hlid.
  split; first by exact hcm.
  split; first by exact hidxe.
  split; first by exact htidxe.
  split; first by exact hkpidxe.
  (* COVERAGE.  The opened index IS the flat index of the u-th coverage tuple,
     so the two lists are EQUAL (cov_step) and the biconditional is the one
     already in hand.  No propositional argument, no injectivity here -- that
     is what phrasing the disjunct over flat indices bought. *)
  have hopen : (fun (z : int * int * int) =>
                  z.`1 %/ l' * l' * k * SPHINCS_PLUS.t
                  + z.`1 %% l' * k * SPHINCS_PLUS.t
                  + z.`2 * SPHINCS_PLUS.t + z.`3)
                 (nth witness (M.F.hC mk{2} m{2}) (size sigFORSTW{2}))
             = tidx{2} * l' * k * SPHINCS_PLUS.t
               + kpidx{2} * k * SPHINCS_PLUS.t
               + size sigFORSTW{2} * SPHINCS_PLUS.t
               + bs2int (rev (take a (drop (a * size sigFORSTW{2})
                                        (FTWES.BLKAL.val cm{2})))).
  + rewrite (hC_nth mk{2} m{2} (size sigFORSTW{2}) _); 1: by smt(size_ge0).
    by rewrite /= -hcm -hidxe -htidxe -hkpidxe.
  (* ORDER MATTERS, and a dump is what settled it: the goal carries the opened
     index as the CODE expression `tidx*l'*k*t + ... + bs2int (...)`, so
     cov_step's `rcons osl (FLATOP (nth ..))` pattern does not match until
     -hopen has folded it back into the coverage tuple.  Rewriting cov_step
     first fails with "nothing to rewrite" -- which reads like a wrong lemma
     and is really a wrong order. *)
  have hnk : 0 <= size sigFORSTW{2} < k by smt(size_ge0).
  rewrite size_rcons -hopen
          -(cov_step FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2}
              mk{2} m{2} (size sigFORSTW{2}) hnk).
  exact hcov.
(* ---------------------------------------------------------------------------
   ENTRY AND EXIT.

   Both programs open with the SAME conditioned draw and then only deterministic
   assignments, so the whole prefix is `wp; rnd; skip` -- the only genuinely
   two-sided step is the coupling on `mk`, and it is the identity coupling.

   The two obligations that are not bookkeeping:

     ENTRY, coverage.  The incoming biconditional is over TUPLES (idxs \in
     lidxs) and the invariant's is over FLAT indices, so the <= direction has to
     turn "some coverage tuple has my flat index" back into "I am that tuple".
     That is the one place injectivity is needed, and flat_pack/flat_inj/
     tuple3_eq are exactly it.

     EXIT, coverage.  size sigFORSTW = k, so the unopened tail is empty
     (cov_exit) and the invariant collapses to the post verbatim.
   --------------------------------------------------------------------------- *)
wp; rnd; skip => &1 &2 hpre.
move: hpre => [hm [hgps [hgad [had2 [hpp [hlid [hlvinv [hxsinv [hcov0 hszlv]]]]]]]]].
(* Normalise the two message copies.  The right computes `mco mkL m{2}` and the
   left `mco mkL m{1}`; with m{1} = m{2} those are the SAME term, and most of
   the left=right conjuncts below then close by reflexivity rather than by an
   argument.  Doing this first is what keeps the entry short. *)
rewrite hm.
(* rnd emits THREE obligations, not one -- support transfer, mu1 transfer, then
   the post -- joined by `&&`.  Asymmetric and again: each split leaves the
   discharged conjunct as a hypothesis of the next, hence the `move=> _`.
   I had guessed this was a plain `forall mk` and it is not; the shape is off a
   cli dump. *)
split; first by [].
move=> _; split; first by [].
move=> _ mkL hmkL.
split; first by [].
move=> _; split; first by [].
move=> _.
(* Routing indices for THIS message key, and their bounds -- FxChain:1551-1568. *)
have hep := edivz_pair (Index.val (FTWES.mco mkL m{2}).`2).
have htbd := edivz_tidx_bound (FTWES.mco mkL m{2}).`2.
have hkbd := edivz_kpidx_bound (FTWES.mco mkL m{2}).`2.
(* Every coverage tuple of this message is in range -- needed in BOTH
   directions of the entry biconditional. *)
have hrng := hC_range mkL m{2}.
split.
(* ======================= LOOP PRECONDITION ======================= *)
+ split; last by [].
  split; first by [].
  split; first by [].
  split; first by [].
  split; first by exact hgps.
  split; first by exact hpp.
  split; first by exact had2.
  split; first by rewrite hgad.
  split; first by [].
  split; first by exact hlvinv.
  split; first by exact hxsinv.
  split; first by exact hszlv.
  split; first by smt(ge1_k).
  split; first by rewrite hep /=; exact htbd.
  split; first by rewrite hep /=; exact hkbd.
  split; first by [].
  split; first by exact hgps.
  split; first by exact hgad.
  (* The ghost target list grows by exactly this message's coverage. *)
  split; first by rewrite flatten_map_hC_rcons -hlid.
  split; first by [].
  split; first by [].
  split; first by rewrite hep /=.
  split; first by rewrite hep /=.
  (* ---- COVERAGE AT ENTRY.  Nothing has been opened yet, so the whole of
     hC mkL m{2} is still in the tail, and the invariant is exactly the
     incoming biconditional WIDENED by that tail.  The <= direction is the one
     place the flat index has to be inverted: the incoming fact is about
     TUPLES and the invariant about FLAT INDICES, so "some coverage tuple has
     my flat index" must become "I AM that tuple" -- flat_pack + flat_inj +
     tuple3_eq, used once, here. ---- *)
  move=> idxs.
  (* `size []` reduces by iota, so /= exposes `drop 0` for drop0.  A
     `(e : t)` ascription is NOT valid EC expression syntax -- that was the
     first attempt here. *)
  rewrite /= drop0 mem_cat.
  split.
  - case.
    * move=> hin.
      have [q1 [q2 [q3 q4]]] : 0 <= idxs.`1 < l /\ 0 <= idxs.`2 < k
                               /\ 0 <= idxs.`3 < SPHINCS_PLUS.t
                               /\ idxs.`1 %/ l' * l' * k * SPHINCS_PLUS.t
                                  + idxs.`1 %% l' * k * SPHINCS_PLUS.t
                                  + idxs.`2 * SPHINCS_PLUS.t + idxs.`3
                                  \in FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2}
        by apply hcov0.
      split; first by exact q1.
      split; first by exact q2.
      split; first by exact q3.
      by rewrite mem_cat; left.
    move=> hin.
    have [q1 [q2 q3]] := hrng idxs hin.
    split; first by exact q1.
    split; first by exact q2.
    split; first by exact q3.
    rewrite mem_cat; right.
    (* map_f must be given f EXPLICITLY: the goal carries the flat index
       EXPANDED, not as a redex `FLATOP idxs`, so bare `apply map_f` is a
       higher-order unification it will not solve. *)
    by apply (map_f (fun (z : int * int * int) =>
                       z.`1 %/ l' * l' * k * SPHINCS_PLUS.t
                       + z.`1 %% l' * k * SPHINCS_PLUS.t
                       + z.`2 * SPHINCS_PLUS.t + z.`3)
                    (M.F.hC mkL m{2}) idxs hin).
  move=> [q1 [q2 [q3 hmm]]].
  move: hmm; rewrite mem_cat; case.
  - by move=> hos; left; apply hcov0.
  move=> /mapP [y [hy hfy]]; right.
  have [r1 [r2 r3]] := hrng y hy.
  have hpx := flat_pack idxs.
  have hpy := flat_pack y.
  have [g1 [g2 g3]] := flat_inj idxs y q2 q3 r2 r3 _.
  - by rewrite -hpx -hpy /= hfy.
  by rewrite (tuple3_eq idxs y g1 g2 g3).
(* ============================ LOOP EXIT ============================ *)
move=> sigL osR sigR hgL hgR.
move=> [[x1 x2]
        [xsig [xm0 [xps [xpp [xad2 [xadL [xskF
          [xlv [xxs [xszlv [xszsig [xtb [xkb [xmk [xgps [xgad [xlid
            [xcm [xidx [xtidxe [xkpidxe xcov]]]]]]]]]]]]]]]]]]]]]].
have hge : k <= size sigR by smt().
split; first by rewrite xsig.
split; first by exact xgps.
split; first by exact xgad.
split; first by exact xad2.
split; first by exact xpp.
split; first by exact xlid.
split; first by exact xlv.
split; first by exact xxs.
split; last by exact xszlv.
(* COVERAGE AT EXIT: size sigR = k, so the unopened tail is empty (cov_exit)
   and the invariant collapses to the post verbatim.  This is the conjunct the
   whole strengthening existed for -- the post names `os_R`, and without it in
   the invariant this goal has no hypothesis mentioning that variable at all. *)
move=> idxs.
by rewrite (xcov idxs) (cov_exit osR mkL m{2} (size sigR) hge).
qed.

(* The T1 bound.  STATED ONLY -- the proof is an admit, and this file reports
   one admit until it is discharged.  Stating it now is not decoration: it is
   what checks that the game instantiates with this reduction (module-type
   ascription, memory restrictions and all), which is the last piece of
   plumbing that can still be wrong for free.  The event on the left is the one
   `t1_term_pinned` above ties to gproc_Q_decomposition's first summand. *)
lemma t1_opre_bound
  (A <: Adv_EUFCMA_Gproc{-O_CMA_Gproc_I, -EUF_CMA_Gproc_I, -EUF_CMA_Gproc_V,
                         -R_OPRE_Gproc, -FTWES.F_OpenPRE.O_SMDTOpenPRE_Default}) &m :
    Pr[EUF_CMA_Gproc_V(A).main() @ &m :
         (res /\ ! EUF_CMA_Gproc_V.covered) /\ EUF_CMA_Gproc_V.valid_OpenPRE]
  <= Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(A),
           FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res].
proof.
(* FRONTIER, dumped 2026-08-07 (0 tactic errors) rather than guessed -- T2's
   lesson was that a stale or assumed goal is what hides defects.  `byequiv => //;
   proc.` yields the two listings:

     LEFT  (EUF_CMA_Gproc_V)          RIGHT (SM_DT_OpenPRE)
     1 ad <- adz                      1 pp <$ dpseed
     2 ps <$ dpseed                   2 tws <@ R_OPRE_Gproc(A).pick()
     3 (pkFORSnt,skFORSnt) <@         3 ys  <@ O_SMDTOpenPRE_Default.init(pp,tws)
         GprocKg.keygen(ps,ad)        4 (i,x) <@ R_OPRE_Gproc(A).find(pp,ys)
     4 O_CMA_Gproc_I.init(..)         5 (tw,y) <@ O.get(i)
     5 (m',sig') <@ A(O_CMA..).forge  6 nrts <@ O.nr_targets()
     ...                              7 opened <@ O.opened(i) ...

   So the alignment is NOT positional: left 1 corresponds to the `ad <- adz`
   INSIDE right 2, and left 3-5 all live inside right 4 (`find` computes the
   public key from the challenge images and then calls forge).  The split point
   therefore has to be taken after inlining pick and find, exactly as T2 did
   with `inline{2} 5; inline{2} 4; seq 4 9`.

   THE FIRST REAL HURDLE, and it is not a research problem: left 3 samples
   `skFORS_ele <$ ddgstblock` and hashes `val skFORS_ele`, while right 3 samples
   `x <$ din = ddgstblocklift` and hashes `x`.  FORS_ES.ec:319 defines
   `ddgstblocklift = dmap ddgstblock DigestBlock.val`, so the two sampling loops
   are related by the standard `rnd DigestBlock.val DigestBlock.insubd`
   bijection -- which is precisely why the F clone is instantiated at the lifted
   distribution.  Establish that correspondence BEFORE the index bookkeeping;
   if it were false the whole reduction would be unsound and no amount of
   loop-invariant work would show it. *)
byequiv => //.
proc.
(* Swap the challenger's FLAT init for the nested one.  `last first` brings the
   side condition (pick emits enough tweaks) to the front, as MM45 does. *)
rewrite equiv [{2} 3 Eqv_OPRE_Init_Orig_ILN]; last first.
+ inline{1} 2; inline{2} 2.
  wp => />.
  while (   ={tidx, adl, pp, R_OPRE_Gproc.ad}
         /\ size adl{1} = tidx{1} * l' * k * SPHINCS_PLUS.t
         /\ 0 <= tidx{1} <= nr_trees 0).
  - wp => /=.
    while (   ={tidx, kpidx, adl, pp, R_OPRE_Gproc.ad}
           /\ size adl{1} = tidx{1} * l' * k * SPHINCS_PLUS.t
                            + kpidx{1} * k * SPHINCS_PLUS.t
           /\ 0 <= tidx{1} < nr_trees 0
           /\ 0 <= kpidx{1} <= l').
    * wp => /=.
      while (   ={tidx, kpidx, tbidx, adl, pp, R_OPRE_Gproc.ad}
             /\ size adl{1} = tidx{1} * l' * k * SPHINCS_PLUS.t
                              + kpidx{1} * k * SPHINCS_PLUS.t + tbidx{1}
             /\ 0 <= tidx{1} < nr_trees 0
             /\ 0 <= kpidx{1} < l'
             /\ 0 <= tbidx{1} <= k * SPHINCS_PLUS.t).
      + by wp; skip => />; smt(size_rcons).
      by wp; skip => />; smt(ge1_k ge2_t).
    by wp; skip => />; smt(FTWES.ge1_l ge1_k ge2_t).
  by wp; rnd; skip => />;
     smt(FTWES.dval FTWES.ge1_s FTWES.ge1_l ge1_k ge2_t).
inline{1} 3; inline{2} 2.
(* SETUP SPLIT.  Left 1-5 are keygen's preamble (assignments + the seed draw);
   right 1-6 are pick's three nested loops building the flattened tweak list.
   The left has NO loop here, so pick's loops are ONE-SIDED (while{2}) and each
   needs a termination measure -- unlike the side condition above, where both
   sides ran the same program and an ordinary two-sided `while` applied. *)
seq 5 6 : (   ={glob A}
           /\ ps{1} = pp{2}
           /\ ps0{1} = pp{2}
           /\ ad{1} = adz
           /\ ad0{1} = adz
           /\ R_OPRE_Gproc.ad{2} = adz
           /\ skFORSnt0{1} = []
           /\ size tws{2} = nr_trees 0 * l' * k * SPHINCS_PLUS.t
           (* The pick/target ordering agreement, now PROVED by the loops above
              and carried out of the setup split.  Still to do: carry it on
              through the sampling-nest and pk invariants -- a broad textual
              sweep matched 9 places and broke, so that carry wants to be done
              per-invariant, not by pattern. *)
           /\ (forall (i0 j0 w : int), 0 <= i0 < nr_trees 0 => 0 <= j0 < l' =>
                 0 <= w < k * SPHINCS_PLUS.t =>
                 nth witness tws{2} (i0 * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t + w)
                 = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                     i0) j0) 0 w)).
+ wp => /=.
  while{2} (   R_OPRE_Gproc.ad{2} = adz
            /\ 0 <= tidx{2} <= nr_trees 0
            /\ size adl{2} = tidx{2} * l' * k * SPHINCS_PLUS.t
            /\ (forall (i0 j0 w : int), 0 <= i0 < tidx{2} => 0 <= j0 < l' =>
                  0 <= w < k * SPHINCS_PLUS.t =>
                  nth witness adl{2} (i0 * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t + w)
                  = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                      i0) j0) 0 w))
           (nr_trees 0 - tidx{2}).
  - move=> &m0 z.
    wp => /=.
    while (   R_OPRE_Gproc.ad = adz
           /\ 0 <= tidx < nr_trees 0
           /\ 0 <= kpidx <= l'
           /\ size adl = tidx * l' * k * SPHINCS_PLUS.t
                         + kpidx * k * SPHINCS_PLUS.t
           /\ (forall (j0 w : int), 0 <= j0 < kpidx => 0 <= w < k * SPHINCS_PLUS.t =>
                 nth witness adl (tidx * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t + w)
                 = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                     tidx) j0) 0 w)
           /\ (forall (i0 j0 w : int), 0 <= i0 < tidx => 0 <= j0 < l' =>
                 0 <= w < k * SPHINCS_PLUS.t =>
                 nth witness adl (i0 * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t + w)
                 = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                     i0) j0) 0 w))
          (l' - kpidx).
    * move=> z2.
      wp => /=.
      while (   R_OPRE_Gproc.ad = adz
             /\ 0 <= tidx < nr_trees 0
             /\ 0 <= kpidx < l'
             /\ 0 <= tbidx <= k * SPHINCS_PLUS.t
             /\ size adl = tidx * l' * k * SPHINCS_PLUS.t
                           + kpidx * k * SPHINCS_PLUS.t + tbidx
             /\ (forall (j0 w : int), 0 <= j0 < kpidx => 0 <= w < k * SPHINCS_PLUS.t =>
                   nth witness adl (tidx * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t + w)
                   = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                       tidx) j0) 0 w)
             /\ (forall (i0 j0 w : int), 0 <= i0 < tidx => 0 <= j0 < l' =>
                   0 <= w < k * SPHINCS_PLUS.t =>
                   nth witness adl (i0 * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t + w)
                   = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                       i0) j0) 0 w)
             /\ (forall (w : int), 0 <= w < tbidx =>
                   nth witness adl (tidx * l' * k * SPHINCS_PLUS.t + kpidx * k * SPHINCS_PLUS.t + w)
                   = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                       tidx) kpidx) 0 w))
            (k * SPHINCS_PLUS.t - tbidx).
      + (* NO `=> />` here: this file already records that it drops the very
           bounds that make an rcons case split work.  The CURRENT keypair's
           entries are at base + w and are linear, but the carried PREVIOUS
           keypairs need j0*k*t + w < kpidx*k*t -- the telescope, i.e. flat_le. *)
        move=> z3; wp; skip => &hr hpre.
        (* Ground the telescope at the stride W = k*t; smt will not instantiate
           flat_le under the carried conjunct's binders on its own. *)
        (* Only ONE of the two re-established conjuncts is non-linear: the
           carried previous keypairs need
             j0*k*t + w < kpidx*k*t   for j0 < kpidx, w < k*t,
           which is the flat_le telescope at stride k*t.  Ground it; the
           current keypair's own entries are linear (base + w). *)
        have hbnd : forall (j0 w : int),
             0 <= j0 < kpidx{hr} => 0 <= w < k * SPHINCS_PLUS.t =>
             tidx{hr} * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t + w < size adl{hr}.
        + move=> j0 w hj hw.
          have h := flat_le (k * SPHINCS_PLUS.t) j0 kpidx{hr} w.
          smt(ge1_k ge2_t).
        (* smt will not chain hbnd -> nth_rcons_lt -> match, so ground the
           carried conjunct itself -- the hc8/hc9/hc10 pattern. *)
        have hprev : forall (j0 w : int),
             0 <= j0 < kpidx{hr} => 0 <= w < k * SPHINCS_PLUS.t =>
             nth witness (rcons adl{hr}
               (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_OPRE_Gproc.ad{hr} trhftype) tidx{hr}) kpidx{hr}) 0 tbidx{hr}))
               (tidx{hr} * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t + w)
             = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                 tidx{hr}) j0) 0 w.
        + move=> j0 w hj hw.
          rewrite nth_rcons_lt; 1: by smt().
          by smt().
        have hcur : forall (w : int), 0 <= w < tbidx{hr} + 1 =>
             nth witness (rcons adl{hr}
               (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_OPRE_Gproc.ad{hr} trhftype) tidx{hr}) kpidx{hr}) 0 tbidx{hr}))
               (tidx{hr} * l' * k * SPHINCS_PLUS.t + kpidx{hr} * k * SPHINCS_PLUS.t + w)
             = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                 tidx{hr}) kpidx{hr}) 0 w.
        + move=> w hw.
          case (w < tbidx{hr}) => [hlt | hge].
          * by rewrite nth_rcons_lt 1:/#; smt().
          have hwe : w = tbidx{hr} by smt().
          have -> : tidx{hr} * l' * k * SPHINCS_PLUS.t + kpidx{hr} * k * SPHINCS_PLUS.t + w
                  = size adl{hr} by smt().
          by rewrite nth_rcons_eq hwe; smt().
        have hassoc : forall (m : int), m * l' * k * SPHINCS_PLUS.t = m * (l' * k * SPHINCS_PLUS.t)
          by move=> m; ring.
        have hbt : forall (i0 j0 w : int),
             0 <= i0 < tidx{hr} => 0 <= j0 < l' => 0 <= w < k * SPHINCS_PLUS.t =>
             i0 * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t + w < size adl{hr}.
        + move=> i0 j0 w hi hj hw.
          have h1 := flat_le (k * SPHINCS_PLUS.t) j0 l' w.
          have h2 := flat_le (l' * (k * SPHINCS_PLUS.t)) i0 tidx{hr} (j0 * k * SPHINCS_PLUS.t + w).
          smt(ge1_k ge2_t FTWES.ge1_l).
        have hpt : forall (i0 j0 w : int),
             0 <= i0 < tidx{hr} => 0 <= j0 < l' => 0 <= w < k * SPHINCS_PLUS.t =>
             nth witness (rcons adl{hr} (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_OPRE_Gproc.ad{hr} trhftype) tidx{hr}) kpidx{hr}) 0 tbidx{hr}))
               (i0 * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t + w)
             = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                 i0) j0) 0 w.
        + by move=> i0 j0 w hi hj hw; rewrite nth_rcons_lt; 1: smt(); smt().
        smt(size_rcons nth_rcons_lt nth_rcons_eq ge1_k ge2_t).
      (* TWO antecedents here, dumped: the loop EXIT GUARD `! tbidx0 < k*t`
         and only then the inner invariant.  Every earlier failure in this
         discharge came from binding the guard and leaving the invariant
         un-introduced -- which is why `[#]` took only two names and why the
         j0 < kpidx branch had nothing to instantiate. *)
      wp; skip => &hr hpre.
      split; 1: by smt(ge1_k ge2_t).
      move=> adl0 tbidx0; split; 1: by smt().
      move=> hguard hinv.
      have hfold : forall (j0 w : int),
           0 <= j0 < kpidx{hr} + 1 => 0 <= w < k * SPHINCS_PLUS.t =>
           nth witness adl0 (tidx{hr} * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t + w)
           = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
               tidx{hr}) j0) 0 w.
      + move=> j0 w hj hw.
        case (j0 < kpidx{hr}) => [hlt | hge]; 1: by smt().
        have hje : j0 = kpidx{hr} by smt().
        by rewrite hje; smt().
      smt(kt_step ge1_k ge2_t).
    (* Same two-antecedent shape as the middle discharge: guard then invariant,
       with a split before each.  NO `=> />`. *)
    wp; skip => &hr hpre.
    split; 1: by smt(FTWES.ge1_l ge1_k ge2_t).
    move=> adl1 kpidx1; split; 1: by smt().
    move=> hguard hinv.
    have hfold : forall (i0 j0 w : int),
         0 <= i0 < tidx{hr} + 1 => 0 <= j0 < l' => 0 <= w < k * SPHINCS_PLUS.t =>
         nth witness adl1 (i0 * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t + w)
         = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i0) j0)
             0 w.
    + move=> i0 j0 w hi hj hw.
      case (i0 < tidx{hr}) => [hlt | hge]; 1: by smt().
      have hie : i0 = tidx{hr} by smt().
      by rewrite hie; smt().
    smt(lt_step FTWES.ge1_l ge1_k ge2_t).
  (* wp / rnd / wp: the trailing assignments, then the paired seed draws, then
     the left's leading `ad <- adz` which sits BEFORE its draw. *)
  by wp; rnd; wp; skip => />; smt(FTWES.ge1_s FTWES.ge1_l ge1_k ge2_t).
inline{2} 1.
(* Absorb the ILN init's preamble (right 1-8: the two argument copies, the four
   oracle-state resets, ys0 and the counter).  The left has nothing here, so
   this is right-only bookkeeping. *)
seq 0 8 : (   ={glob A}
           /\ ps{1} = pp{2}
           /\ ps0{1} = pp{2}
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
           /\ ad{1} = adz
           /\ ad0{1} = adz
           /\ R_OPRE_Gproc.ad{2} = adz
           /\ skFORSnt0{1} = []
           /\ tws_init{2} = tws{2}
           /\ size tws{2} = nr_trees 0 * l' * k * SPHINCS_PLUS.t
           /\ (forall (i1 j1 w1 : int), 0 <= i1 < nr_trees 0 => 0 <= j1 < l' =>
                 0 <= w1 < k * SPHINCS_PLUS.t =>
                 nth witness tws{2} (i1 * l' * k * SPHINCS_PLUS.t
                                     + j1 * k * SPHINCS_PLUS.t + w1)
                 = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                     i1) j1) 0 w1)
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} = []
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2} = []
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2} = []
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
           /\ ys0{2} = []
           /\ i0{2} = 0).
+ by wp; skip => />.
(* THE SAMPLING NESTS, aligned.  Left 1 is keygen's sk cube, right 1 is the
   (now nested) challenger init; the loop reformatting above is what made these
   the same shape, and Eqv_sampling_bridge is what pairs their innermost draws.

   The invariant carries four things, and the third is the one that matters for
   soundness rather than bookkeeping:
     - the counters agree (size skFORSnt0{1} = i0{2}), which is also what makes
       the two loop GUARDS agree so a two-sided `while` applies at all;
     - sizes: xs grows exactly l'*k*t per outer step, ts tracks xs, and
       ys0 is unzip2 ts;
     - ts is (tweak, f pp tweak preimage) at the FLAT index -- stated over a
       single idx rather than MM45's four, which is where the pick/target
       ordering agreement actually gets pinned;
     - xs at the flat index is `val` of the nested secret element.  This is the
       reduction's whole point: the challenger's hidden preimages ARE the FORS
       secret key.
   All four levels are PROVED, and the invariant also carries os{2} = [] and
   the tws characterisation (the pick/target ordering agreement).  This file
   now reports ONE admit, and it is not here. *)
seq 1 1 : (   ={glob A}
           /\ ps{1} = pp{2}
           /\ ps0{1} = pp{2}
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
           /\ ad{1} = adz
           /\ ad0{1} = adz
           /\ R_OPRE_Gproc.ad{2} = adz
           /\ tws_init{2} = tws{2}
           /\ size tws{2} = nr_trees 0 * l' * k * SPHINCS_PLUS.t
           /\ (forall (i1 j1 w1 : int), 0 <= i1 < nr_trees 0 => 0 <= j1 < l' =>
                 0 <= w1 < k * SPHINCS_PLUS.t =>
                 nth witness tws{2} (i1 * l' * k * SPHINCS_PLUS.t
                                     + j1 * k * SPHINCS_PLUS.t + w1)
                 = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                     i1) j1) 0 w1)
           /\ size skFORSnt0{1} = i0{2}
           /\ 0 <= i0{2} <= nr_trees 0
           /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
              = i0{2} * l' * k * SPHINCS_PLUS.t
           /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
              = size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
           /\ ys0{2} = unzip2 FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
               /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2} = []
               /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
           /\ (forall (idx : int),
                 0 <= idx < size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} =>
                 nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} idx
                 = (nth witness tws{2} idx,
                    f pp{2} (nth witness tws{2} idx)
                      (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2} idx)))
           /\ (forall (i j u v : int),
                 0 <= i < i0{2} => 0 <= j < l' =>
                 0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
                 nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                   (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                    + u * SPHINCS_PLUS.t + v)
                 = DigestBlock.val
                     (nth witness
                       (nth witness
                         (FTWES.DBLLKTL.val
                           (nth witness (nth witness skFORSnt0{1} i) j)) u) v))
           /\ i0{2} = nr_trees 0).
+ while (   ={glob A}
           /\ ps{1} = pp{2}
           /\ ps0{1} = pp{2}
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
           /\ ad{1} = adz
           /\ ad0{1} = adz
           /\ R_OPRE_Gproc.ad{2} = adz
           /\ tws_init{2} = tws{2}
           /\ size tws{2} = nr_trees 0 * l' * k * SPHINCS_PLUS.t
           /\ (forall (i1 j1 w1 : int), 0 <= i1 < nr_trees 0 => 0 <= j1 < l' =>
                 0 <= w1 < k * SPHINCS_PLUS.t =>
                 nth witness tws{2} (i1 * l' * k * SPHINCS_PLUS.t
                                     + j1 * k * SPHINCS_PLUS.t + w1)
                 = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                     i1) j1) 0 w1)
           /\ size skFORSnt0{1} = i0{2}
           /\ 0 <= i0{2} <= nr_trees 0
           /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
              = i0{2} * l' * k * SPHINCS_PLUS.t
           /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
              = size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
           /\ ys0{2} = unzip2 FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
               /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2} = []
               /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
           /\ (forall (idx : int),
                 0 <= idx < size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} =>
                 nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} idx
                 = (nth witness tws{2} idx,
                    f pp{2} (nth witness tws{2} idx)
                      (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2} idx)))
           /\ (forall (i j u v : int),
                 0 <= i < i0{2} => 0 <= j < l' =>
                 0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
                 nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                   (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                    + u * SPHINCS_PLUS.t + v)
                 = DigestBlock.val
                     (nth witness
                       (nth witness
                         (FTWES.DBLLKTL.val
                           (nth witness (nth witness skFORSnt0{1} i) j)) u) v))).
  - (* OUTER BODY.  wp absorbs `skFORSnt0 <- rcons ..` / `i0 <- i0 + 1`; the
       l'-loop below is level 2.  Its invariant repeats the stable facts and
       adds the CURRENT outer entry's partial correspondence, phrased directly
       through FTWES.DBLLKTL.val so that folding it into the outer invariant at
       exit is a rewrite rather than a subtype round-trip. *)
    wp => /=.
    while (   ={glob A}
           /\ ps{1} = pp{2}
           /\ ps0{1} = pp{2}
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
           /\ ad{1} = adz
           /\ ad0{1} = adz
           /\ R_OPRE_Gproc.ad{2} = adz
           /\ tws_init{2} = tws{2}
           /\ size tws{2} = nr_trees 0 * l' * k * SPHINCS_PLUS.t
           /\ (forall (i1 j1 w1 : int), 0 <= i1 < nr_trees 0 => 0 <= j1 < l' =>
                 0 <= w1 < k * SPHINCS_PLUS.t =>
                 nth witness tws{2} (i1 * l' * k * SPHINCS_PLUS.t
                                     + j1 * k * SPHINCS_PLUS.t + w1)
                 = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                     i1) j1) 0 w1)
           /\ size skFORSnt0{1} = i0{2}
           /\ 0 <= i0{2} < nr_trees 0
           /\ size skFORSlp{1} = j{2}
           /\ 0 <= j{2} <= l'
           /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
              = i0{2} * l' * k * SPHINCS_PLUS.t + j{2} * k * SPHINCS_PLUS.t
           /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
              = size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
           /\ ys0{2} = unzip2 FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
               /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2} = []
               /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
           /\ (forall (idx : int),
                 0 <= idx < size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} =>
                 nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} idx
                 = (nth witness tws{2} idx,
                    f pp{2} (nth witness tws{2} idx)
                      (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2} idx)))
           /\ (forall (i j0 u v : int),
                 0 <= i < i0{2} => 0 <= j0 < l' =>
                 0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
                 nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                   (i * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t
                    + u * SPHINCS_PLUS.t + v)
                 = DigestBlock.val
                     (nth witness
                       (nth witness
                         (FTWES.DBLLKTL.val
                           (nth witness (nth witness skFORSnt0{1} i) j0)) u) v))
           /\ (forall (j0 u v : int),
                 0 <= j0 < j{2} => 0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
                 nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                   (i0{2} * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t
                    + u * SPHINCS_PLUS.t + v)
                 = DigestBlock.val
                     (nth witness
                       (nth witness
                         (FTWES.DBLLKTL.val (nth witness skFORSlp{1} j0)) u) v))).
    * (* LEVEL 3 (the k loop).  New conjuncts over level 2: the cube's SHAPE
         (size = u, every row of length t), which exists solely so the fold can
         apply DBLLKTL.insubdK, and the current-j partial correspondence -- at
         this level over the RAW cube, since the subtype wrapper is only put on
         at the fold. *)
      wp => /=.
      while (   ={glob A}
             /\ ps{1} = pp{2}
             /\ ps0{1} = pp{2}
             /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
             /\ ad{1} = adz
             /\ ad0{1} = adz
             /\ R_OPRE_Gproc.ad{2} = adz
             /\ tws_init{2} = tws{2}
             /\ size tws{2} = nr_trees 0 * l' * k * SPHINCS_PLUS.t
             /\ (forall (i1 j1 w1 : int), 0 <= i1 < nr_trees 0 => 0 <= j1 < l' =>
                   0 <= w1 < k * SPHINCS_PLUS.t =>
                   nth witness tws{2} (i1 * l' * k * SPHINCS_PLUS.t
                                       + j1 * k * SPHINCS_PLUS.t + w1)
                   = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                       i1) j1) 0 w1)
             /\ size skFORSnt0{1} = i0{2}
             /\ 0 <= i0{2} < nr_trees 0
             /\ size skFORSlp{1} = j{2}
             /\ 0 <= j{2} < l'
             /\ size skFORScube{1} = u{2}
             /\ 0 <= u{2} <= k
             /\ all (fun (ls : dgstblock list) => size ls = SPHINCS_PLUS.t)
                     skFORScube{1}
             /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                = i0{2} * l' * k * SPHINCS_PLUS.t + j{2} * k * SPHINCS_PLUS.t
                  + u{2} * SPHINCS_PLUS.t
             /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
                = size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
             /\ ys0{2} = unzip2 FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
               /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2} = []
               /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
             /\ (forall (idx : int),
                   0 <= idx < size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} =>
                   nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} idx
                   = (nth witness tws{2} idx,
                      f pp{2} (nth witness tws{2} idx)
                        (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2} idx)))
             /\ (forall (i j0 u0 v0 : int),
                   0 <= i < i0{2} => 0 <= j0 < l' =>
                   0 <= u0 < k => 0 <= v0 < SPHINCS_PLUS.t =>
                   nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                     (i * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t
                      + u0 * SPHINCS_PLUS.t + v0)
                   = DigestBlock.val
                       (nth witness (nth witness (FTWES.DBLLKTL.val
                         (nth witness (nth witness skFORSnt0{1} i) j0)) u0) v0))
             /\ (forall (j0 u0 v0 : int),
                   0 <= j0 < j{2} => 0 <= u0 < k => 0 <= v0 < SPHINCS_PLUS.t =>
                   nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                     (i0{2} * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t
                      + u0 * SPHINCS_PLUS.t + v0)
                   = DigestBlock.val
                       (nth witness (nth witness (FTWES.DBLLKTL.val
                         (nth witness skFORSlp{1} j0)) u0) v0))
             /\ (forall (u0 v0 : int),
                   0 <= u0 < u{2} => 0 <= v0 < SPHINCS_PLUS.t =>
                   nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                     (i0{2} * l' * k * SPHINCS_PLUS.t + j{2} * k * SPHINCS_PLUS.t
                      + u0 * SPHINCS_PLUS.t + v0)
                   = DigestBlock.val
                       (nth witness (nth witness skFORScube{1} u0) v0))).
      + (* LEVEL 4 (the t loop) -- the innermost, and the only one that actually
           SAMPLES.  New conjuncts: the row counter and the current-u partial
           correspondence over the RAW row skFORSet. *)
        wp => /=.
        while (={glob A}
               /\ ps{1} = pp{2}
               /\ ps0{1} = pp{2}
               /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
               /\ ad{1} = adz
               /\ ad0{1} = adz
               /\ R_OPRE_Gproc.ad{2} = adz
               /\ tws_init{2} = tws{2}
               /\ size tws{2} = nr_trees 0 * l' * k * SPHINCS_PLUS.t
               /\ (forall (i1 j1 w1 : int), 0 <= i1 < nr_trees 0 => 0 <= j1 < l' =>
                     0 <= w1 < k * SPHINCS_PLUS.t =>
                     nth witness tws{2} (i1 * l' * k * SPHINCS_PLUS.t
                                         + j1 * k * SPHINCS_PLUS.t + w1)
                     = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                         i1) j1) 0 w1)
               /\ size skFORSnt0{1} = i0{2}
               /\ 0 <= i0{2} < nr_trees 0
               /\ size skFORSlp{1} = j{2}
               /\ 0 <= j{2} < l'
               /\ size skFORScube{1} = u{2}
               /\ 0 <= u{2} < k
               /\ all (fun (ls : dgstblock list) => size ls = SPHINCS_PLUS.t)
                       skFORScube{1}
               /\ size skFORSet{1} = v{2}
               /\ 0 <= v{2} <= SPHINCS_PLUS.t
               /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                  = i0{2} * l' * k * SPHINCS_PLUS.t + j{2} * k * SPHINCS_PLUS.t
                    + u{2} * SPHINCS_PLUS.t + v{2}
               /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
                  = size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
               /\ ys0{2} = unzip2 FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
               /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2} = []
               /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
               /\ (forall (idx : int),
                     0 <= idx < size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} =>
                     nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} idx
                     = (nth witness tws{2} idx,
                        f pp{2} (nth witness tws{2} idx)
                          (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2} idx)))
               /\ (forall (i j0 u0 v0 : int),
                     0 <= i < i0{2} => 0 <= j0 < l' =>
                     0 <= u0 < k => 0 <= v0 < SPHINCS_PLUS.t =>
                     nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                       (i * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t
                        + u0 * SPHINCS_PLUS.t + v0)
                     = DigestBlock.val
                         (nth witness (nth witness (FTWES.DBLLKTL.val
                           (nth witness (nth witness skFORSnt0{1} i) j0)) u0) v0))
               /\ (forall (j0 u0 v0 : int),
                     0 <= j0 < j{2} => 0 <= u0 < k => 0 <= v0 < SPHINCS_PLUS.t =>
                     nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                       (i0{2} * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t
                        + u0 * SPHINCS_PLUS.t + v0)
                     = DigestBlock.val
                         (nth witness (nth witness (FTWES.DBLLKTL.val
                           (nth witness skFORSlp{1} j0)) u0) v0))
               /\ (forall (u0 v0 : int),
                     0 <= u0 < u{2} => 0 <= v0 < SPHINCS_PLUS.t =>
                     nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                       (i0{2} * l' * k * SPHINCS_PLUS.t + j{2} * k * SPHINCS_PLUS.t
                        + u0 * SPHINCS_PLUS.t + v0)
                     = DigestBlock.val
                         (nth witness (nth witness skFORScube{1} u0) v0))
               /\ (forall (v0 : int),
                     0 <= v0 < v{2} =>
                     nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                       (i0{2} * l' * k * SPHINCS_PLUS.t + j{2} * k * SPHINCS_PLUS.t
                        + u{2} * SPHINCS_PLUS.t + v0)
                     = DigestBlock.val (nth witness skFORSet{1} v0))).
        - (* THE SAMPLING STEP.  Eqv_sampling_bridge proved this pairing in
             isolation; here it is inlined because the surrounding rcons
             bookkeeping has to be re-established in the same breath. *)
          wp => /=.
          rnd DigestBlock.val DigestBlock.insubd.
          (* `skip => />` leaves `forall &1 &2, H => H => ...` here (unlike the
             isolated bridge, which had no hypotheses), so the memories and
             hypotheses must be introduced BEFORE any split -- otherwise the
             first split reports "cannot apply split/None on that goal". *)
          (* NAMED, not `*`.  The 19 invariant conjuncts used to land anonymous,
             which is what made the final discharge below the heaviest smt call
             in the file: every one of its 13 subgoals had to search 19 unnamed
             hypotheses, four of them large `forall`s.  Arity and order are READ
             OFF a cli dump of the discharge goal, not counted by eye. *)
          wp; skip => />; move=> &1 &2 htws htwsc hnt0 hnt1 hlp0 hlp1 hcb0 hcb1
                                   hallc het0 het1 hszx hszt htsc hout hjc huc
                                   hvc hgd.
          (* The (val, insubd) bijection, discharged exactly as in
             Eqv_sampling_bridge -- right-cancel, mu1 transfer via
             in_dmap1E_can, support membership, left-cancel. *)
          split => [x /supp_dmap [x'] [_ ->] | vibij];
            1: by rewrite DigestBlock.valKd.
          split => [x /supp_dmap [x'] [xin xval] | eqmu1vi skfele skfelein].
          + by rewrite &(in_dmap1E_can) 1:DigestBlock.insubdK 1:xval
                       1:DigestBlock.valP 1,2:// => y _ <-;
               rewrite DigestBlock.valKd.
          split => [| vskfelein]; 1: rewrite supp_dmap; 1: by exists skfele.
          split => [ | _]; 1: by rewrite DigestBlock.valKd.
          (* unzip2 is an ABBREV for `map snd`, so map_rcons does not fire as an
             smt hint through it; hand over the directed equation instead. *)
          (* Stated over an EXPLICIT PAIR (a, b), not over `x` with `x.`2`: the
             goal's element is the pair's second component already reduced, so
             the `x.`2` form needs a projection reduction inside `map` that smt
             does not perform. *)
          have hun : forall (s : (adrs * dgstblock) list) (a : adrs)
                            (b : dgstblock),
                       unzip2 (rcons s (a, b)) = rcons (unzip2 s) b
            by move=> s a b; rewrite map_rcons.
          (* Kimi K3's script (2026-08-07), applied after its read was tested
             rather than banked.  Two corrections it made to mine, both real:
             (a) flat_idx_lt is strict only in the l'*k*t block, so it covers
                 ONLY the outer conjunct -- the level-2 and level-3 conjuncts
                 need the k*t and t telescopes, hence flat_le;
             (b) nth_rcons_lt's guard is `0 <= i < size s`, TWO-sided, and
                 FTWES.ge1_l / ge1_k / ge2_t were absent from every hint list I
                 tried, so even the linear conjuncts could not close.  That is
                 also why reshaping `hun` was doomed: hun was never the blocker. *)
          have hb_out : forall (i1 j0 u0 v0 : int),
               0 <= i1 => i1 < size skFORSnt0{1}
            => 0 <= j0 => j0 < l' => 0 <= u0 => u0 < k
            => 0 <= v0 => v0 < SPHINCS_PLUS.t
            => i1 * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t
               + u0 * SPHINCS_PLUS.t + v0
               < size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}.
          + move=> i1 j0 u0 v0 *.
            by have := flat_idx_lt i1 j0 u0 v0 (size skFORSnt0{1})
                 (size skFORSlp{1}) (size skFORScube{1}) (size skFORSet{1});
               smt().
          have hb_j : forall (j0 u0 v0 : int),
               0 <= j0 => j0 < size skFORSlp{1}
            => 0 <= u0 => u0 < k => 0 <= v0 => v0 < SPHINCS_PLUS.t
            => j0 * k * SPHINCS_PLUS.t + u0 * SPHINCS_PLUS.t + v0
               <= size skFORSlp{1} * k * SPHINCS_PLUS.t - 1.
          + move=> j0 u0 v0 hj0 hj hu0 hu hv0 hv.
            have s1 : u0 * SPHINCS_PLUS.t + v0 <= k * SPHINCS_PLUS.t - 1.
            + by have := flat_le SPHINCS_PLUS.t u0 k v0; smt(ge2_t).
            by have := flat_le (k * SPHINCS_PLUS.t) j0 (size skFORSlp{1})
                         (u0 * SPHINCS_PLUS.t + v0); smt(ge1_k ge2_t).
          have hb_u : forall (u0 v0 : int),
               0 <= u0 => u0 < size skFORScube{1}
            => 0 <= v0 => v0 < SPHINCS_PLUS.t
            => u0 * SPHINCS_PLUS.t + v0
               <= size skFORScube{1} * SPHINCS_PLUS.t - 1.
          + by move=> u0 v0 hu0 hu hv0 hv;
              have := flat_le SPHINCS_PLUS.t u0 (size skFORScube{1}) v0;
              smt(ge2_t).
          (* Each correspondence conjunct gets its own ground `have`, and inside
             it BOTH halves of nth_rcons_lt's guard are grounded too -- smt will
             not chain (instantiate bound) -> (rewrite) -> (match) by itself,
             and it will not instantiate hb_* under the conjunct's own binders
             either.  Four levels of this proof have now taught the same rule. *)
          have hslack : 0 <= size skFORScube{1} * SPHINCS_PLUS.t
                             + size skFORSet{1}
            by smt(mulr_ge0 ge2_t size_ge0).
          have hc8 : forall (i1 j0 u0 v0 : int),
               0 <= i1 => i1 < size skFORSnt0{1}
            => 0 <= j0 => j0 < l' => 0 <= u0 => u0 < k
            => 0 <= v0 => v0 < SPHINCS_PLUS.t
            => nth witness
                 (rcons FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                    (DigestBlock.val skfele))
                 (i1 * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t
                  + u0 * SPHINCS_PLUS.t + v0)
               = DigestBlock.val
                   (nth witness (nth witness (FTWES.DBLLKTL.val
                     (nth witness (nth witness skFORSnt0{1} i1) j0)) u0) v0).
          + move=> i1 j0 u0 v0 hi0 hi hj0 hj hu0 hu hv0 hv.
            rewrite nth_rcons_lt; 1: by smt(flat_idx_ge0).
            by smt().
          have hc9 : forall (j0 u0 v0 : int),
               0 <= j0 => j0 < size skFORSlp{1}
            => 0 <= u0 => u0 < k => 0 <= v0 => v0 < SPHINCS_PLUS.t
            => nth witness
                 (rcons FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                    (DigestBlock.val skfele))
                 (size skFORSnt0{1} * l' * k * SPHINCS_PLUS.t
                  + j0 * k * SPHINCS_PLUS.t + u0 * SPHINCS_PLUS.t + v0)
               = DigestBlock.val
                   (nth witness (nth witness (FTWES.DBLLKTL.val
                     (nth witness skFORSlp{1} j0)) u0) v0).
          + move=> j0 u0 v0 hj0 hj hu0 hu hv0 hv.
            have hup := hb_j j0 u0 v0 hj0 hj hu0 hu hv0 hv.
            have hlo := flat_idx_ge0 (size skFORSnt0{1}) j0 u0 v0
                          (size_ge0 skFORSnt0{1}) hj0 hu0 hv0.
            rewrite nth_rcons_lt; 1: by smt().
            by smt().
          have hc10 : forall (u0 v0 : int),
               0 <= u0 => u0 < size skFORScube{1}
            => 0 <= v0 => v0 < SPHINCS_PLUS.t
            => nth witness
                 (rcons FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                    (DigestBlock.val skfele))
                 (size skFORSnt0{1} * l' * k * SPHINCS_PLUS.t
                  + size skFORSlp{1} * k * SPHINCS_PLUS.t
                  + u0 * SPHINCS_PLUS.t + v0)
               = DigestBlock.val
                   (nth witness (nth witness skFORScube{1} u0) v0).
          + move=> u0 v0 hu0 hu hv0 hv.
            have hup := hb_u u0 v0 hu0 hu hv0 hv.
            have hlo := flat_idx_ge0 (size skFORSnt0{1}) (size skFORSlp{1})
                          u0 v0 (size_ge0 skFORSnt0{1}) (size_ge0 skFORSlp{1})
                          hu0 hv0.
            rewrite nth_rcons_lt; 1: by smt().
            by smt().
          (* WAS THE HEAVIEST SMT CALL IN THE FILE; GROUNDED 2026-08-09.
             History kept because two of my diagnoses of it were WRONG, and the
             retraction is the useful part.

             The old tactic was
               by do! split; smt(size_rcons nth_rcons_lt nth_rcons_eq
                                 FTWES.ge1_l ge1_k ge2_t).
             Thirteen subgoals, each handed all 19 (then ANONYMOUS) invariant
             conjuncts plus six hints, with both rcons case-splits left for
             axiom selection to find.  Symptoms, all measured:
               - failed under CONCURRENT load (found by running two must-fail
                 controls in parallel and getting a failure HERE from an edit
                 450 lines below, whose diff could not reach this step);
               - failed under the GATE's invocation -- every .eco purged under
                 base-c10-split, cdrafts-split and scratch, then
                 `-I base-c10-split -I cdrafts-split -I scratch` -- while the
                 same file with a warm .eco cache compiled clean.

             TWO WRONG DIAGNOSES, retracted.  (1) "It is over budget and PHASE
             1f has been passing it on luck": not established -- that came from
             a one-variable revert that left stale .eco in scratch.  (2) "It is
             a stale-.eco/include-path interaction": killed by the gate
             reproducing RED after its own purge.  What WAS established, both
             variables controlled, is that the failure did not depend on the
             file's content: 1fdb62c:scratch/_t1.ec -- byte-identical to a file
             PHASE 1f had ACCEPTED -- failed at this step under the same
             conditions.

             The fix is the one that was obvious once the goal was dumped
             instead of theorised about: name the conjuncts, discharge each by
             name, and stop asking axiom selection to re-derive hc8/hc9/hc10,
             which are proved immediately above.  Measured after grounding:
             full purge + the gate's include path now compiles CLEAN.  No claim
             is made here about which of the two symptoms shared a mechanism --
             that was never isolated, and grounding made it moot. *)
          (* GROUNDED, 2026-08-09.  Was `do! split; smt(size_rcons nth_rcons_lt
             nth_rcons_eq FTWES.ge1_l ge1_k ge2_t)`: thirteen subgoals, each
             handed the whole context and six hints, with the two rcons
             case-splits (C6, C10) left for axiom selection to rediscover.
             Now every conjunct is discharged by name.  Three of them ARE
             hc8/hc9/hc10, already proved immediately above -- they were being
             re-searched rather than applied. *)
          split; last by smt(size_rcons).
          split; first by rewrite size_rcons.
          split; first by smt(size_ge0).
          split; first by rewrite size_rcons hszx; smt().
          split; first by rewrite !size_rcons hszt.
          split; first by rewrite hun.
          (* C6: the ts characterisation, one rcons step on.  Case split on
             whether the index is an old entry or the one just appended -- the
             step smt was being asked to find by itself. *)
          split.
          + move=> idx0 h0 h1.
            rewrite size_rcons in h1.
            case (idx0 < size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2})
              => hlt.
            - rewrite nth_rcons_lt; 1: by smt().
              rewrite nth_rcons_lt; 1: by smt().
              by apply htsc.
            have hid : idx0 = size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
              by smt().
            by rewrite hid nth_rcons_eq hszt nth_rcons_eq hszx.
          split; first by exact hc8.
          split; first by exact hc9.
          split; first by exact hc10.
          (* C10: same case split, one level down (the element list). *)
          move=> v0 h0 h1.
          case (v0 < size skFORSet{1}) => hlt.
          + rewrite nth_rcons_lt; 1: by smt(flat_idx_ge0).
            rewrite nth_rcons_lt; 1: by smt().
            by apply hvc.
          have hid : v0 = size skFORSet{1} by smt().
          by rewrite hid -hszx !nth_rcons_eq.
        (* LEVEL-4 -> LEVEL-3 FOLD.  Arity measured (8, same shape as level 3
           one level down).  Same three ingredients as every fold before it:
           hoist the exit equality, ground the current-level correspondence,
           hand over the ring fact. *)
        wp; skip => &1 &2 pre.
        split; 1: by smt(ge2_t ge1_k FTWES.ge1_l).
        move=> row tsR xsR vR ysR g1 g2 hinv.
        have hvt : vR = SPHINCS_PLUS.t by smt().
        have hall : all (fun (ls : dgstblock list) => size ls = SPHINCS_PLUS.t)
                        (rcons skFORScube{1} row)
          by rewrite -cats1 all_cat /=; smt().
        have hcur4 : forall (v0 : int),
             0 <= v0 < SPHINCS_PLUS.t
          => nth witness xsR
               (i0{2} * l' * k * SPHINCS_PLUS.t + j{2} * k * SPHINCS_PLUS.t
                + u{2} * SPHINCS_PLUS.t + v0)
             = DigestBlock.val (nth witness row v0).
        + by move=> v0 hv0; smt().
        have key := fold_rcons_corr_u xsR skFORScube{1} row
                      (i0{2} * l' * k * SPHINCS_PLUS.t
                       + j{2} * k * SPHINCS_PLUS.t) u{2} _ _ _ hcur4;
          1..3: by smt().
        have harith : (u{2} + 1) * SPHINCS_PLUS.t
                    = u{2} * SPHINCS_PLUS.t + SPHINCS_PLUS.t by ring.
        by smt(size_rcons).
      (* LEVEL-3 FOLD.  Intro arity measured (8) and TYPES read off a goal dump
         rather than inferred from level 2's shape -- level 2 had 5, and the
         extra three here are the cube, the u counter and ys0.  Order:
           cube, ts, xs, u, ys0, then the two exit guards, then the invariant.
         The size conjunct again needs a ring fact handed over ((j+1)*k*t is
         not j*k*t + k*t to smt), which is exactly what cost five attempts one
         level up. *)
      wp; skip => &1 &2 pre.
      split; 1: by smt(FTWES.ge1_l ge1_k ge2_t).
      move=> cube tsR xsR uR ysR g1 g2 hinv.
      (* Premises 1-5 discharge; premise 6 (hcur) does NOT, confirmed by
         bisection rather than by suspicion.  The reason is narrow: premise 5
         wants `j0 < j{2}` and the invariant supplies exactly that, whereas
         premise 6 wants `u0 < k` and the invariant supplies `u0 < uR`.  The
         exit guard gives uR = k, but that substitution has to happen INSIDE a
         universally quantified hypothesis buried in a conjunction, which smt
         will not do.  Supplying premise 6 as a ground-instantiated `have`
         turns it into a per-(u0,v0) fact and it goes through. *)
      (* uR = k is needed twice -- inside hcur6 AND by the size conjunct of the
         level-2 invariant (size xs = i0*l'*k*t + j*k*t + uR*t has to become
         i0*l'*k*t + (j+1)*k*t) -- so hoist it instead of proving it locally. *)
      have huk : uR = k by smt().
      have hcur6 : forall (u0 v0 : int),
        0 <= u0 < k => 0 <= v0 < SPHINCS_PLUS.t =>
        nth witness xsR (i0{2} * l' * k * SPHINCS_PLUS.t
                         + j{2} * k * SPHINCS_PLUS.t
                         + u0 * SPHINCS_PLUS.t + v0)
        = DigestBlock.val (nth witness (nth witness cube u0) v0).
      + by move=> u0 v0 hu0 hv0; smt().
      have key := fold_rcons_corr_j xsR skFORSlp{1} cube
                    (i0{2} * l' * k * SPHINCS_PLUS.t) j{2} _ _ _ _ _ hcur6;
        1..5: by smt().
      have harith : (j{2} + 1) * k * SPHINCS_PLUS.t
                  = j{2} * k * SPHINCS_PLUS.t + k * SPHINCS_PLUS.t by ring.
      by smt(size_rcons).
    (* THE FOLD, dumped and characterised, NOT yet discharged.  It must derive
         forall i1 < i0+1, .. nth (rcons skFORSnt0 skFORSlp) i1 ..
       from the outer conjunct (i1 < i0, over skFORSnt0) plus the level-2
       conjunct (j0 < l', over skFORSlp).  That is a case split on i1 = i0
       under THREE layers of nth plus a DigestBlock.val, and smt does not find
       it from `nth_rcons` as a hint alone -- two widened hint lists failed
       with "cannot prove goal (strict)".  It wants the split done by hand.
       Recorded rather than guessed at a third time. *)
    wp; skip => &1 &2 pre.
    split; 1: by smt(FTWES.ge1_l ge1_k ge2_t FTWES.ge1_s).
    (* Arity measured (over-supplied names, read the error line): exactly five
       hypotheses after the three loop-modified variables.  The helper is then
       instantiated EXPLICITLY -- smt will not find it on its own, which three
       hint lists confirmed. *)
    move=> skl tsR xsR h1 h2 h3 h4 h5.
    have key := fold_rcons_corr xsR skFORSnt0{1} skl i0{2} _ _ _ _;
      1..4: by smt().
    (* The dump settled it, and the fold was NOT the problem: `key` is
       SYNTACTICALLY the conclusion's last conjunct.  What smt could not do is
       the SIZE conjunct -- from size xsR = i0*l'*k*t + j*k*t with j = l' at
       exit, it has to see
         (i0 + 1) * l' * k * t = i0 * l' * k * t + l' * k * t,
       four-factor distributivity, which is `ring` work and not smt work.
       Handing it over as a hypothesis closes the whole post.  Five earlier
       attempts all aimed at the fold; none of them could ever have worked. *)
    have harith : (i0{2} + 1) * l' * k * SPHINCS_PLUS.t
                = i0{2} * l' * k * SPHINCS_PLUS.t + l' * k * SPHINCS_PLUS.t
      by ring.
    (* GROUNDED REWORK, forced by carrying the tws characterisation.  The post
       is now an EIGHTEEN-way conjunction whose tenth member is a quantified
       equation over four nested address setters, and the single
       `by smt(size_rcons)` that closed the pre-carry goal no longer does:
       every OTHER conjunct is unchanged, so what broke is search budget, not
       provability.  Confirmed narrowly -- a full compile of the carried file
       reports exactly ONE failure, here; all three inner folds, every body
       preservation and both entries take the extra conjunct for free.
       So peel the invariant to depth 10 (which stops short of the two
       `0 <= _ <= _` ranges at positions 12 and 14, whose ranges `[..]` would
       otherwise split), close the first nine by assumption, discharge the
       carried conjunct by APPLY -- no search at all, it is syntactically
       htws -- and hand what remains to the tactic that already proved it. *)
    move: h5 => [ha [hb [hc [hd [he [hf [hg [hh [hi [htws h5r]]]]]]]]]].
    split; last by smt(size_rcons).
    do 9! (split; first by smt()).
    split; first by apply htws.
    by do! split; smt(size_rcons).
  (* NOT `skip => />`: at entry skFORSnt0{1} = [] and i0{2} = 0, so the
     correspondence conjunct is VACUOUS -- and /> eagerly rewrites
     `nth witness [] i` to `witness` while dropping the `0 <= i < 0` bound that
     made it vacuous, leaving an unprovable `witness = val (...)`.  Dumped
     rather than guessed.
     The carry then broke this too, and the dump shows why the one-liner had to
     go: the goal is (ENTRY-INV /\ guard-iff) /\ (forall exit-vars, !g1 => !g2
     => INV => POST), so the carried conjunct has to be re-established TWICE
     against two different premises -- position 11 of the seq-0-8 post on the
     way in, position 10 of the invariant on the way out.  Both are verbatim
     pass-throughs (no loop here writes tws), so both are discharged by APPLY
     after peeling; only the depth differs, and the depths are read off the
     dump rather than guessed. *)
  skip => &1 &2 hpre.
  move: hpre => [qa [qb [qc [qd [qe [qf [qg [qh [qi [qj [qtws qrest]]]]]]]]]]].
  split.
  + split; last by smt(FTWES.ge1_s).
    do 9! (split; first by smt()).
    split; first by apply qtws.
    by do! split; smt(FTWES.ge1_s).
  move=> sknt tsR xsR i0R ys0R g1 g2 hinv.
  move: hinv => [ra [rb [rc [rd [re [rf [rg [rh [ri [rtws rrest]]]]]]]]]].
  do 9! (split; first by smt()).
  split; first by apply rtws.
  by do! split; smt(FTWES.ge1_s).
(* SECOND HALF: the reduction's find() builds the public key out of the
   CHALLENGE IMAGES and only then calls forge, so the pk loops align against
   keygen's pk loops with the leaf correspondence established above. *)
inline{2} 2.
(* `sp` rather than `seq`: left 1 and right 1-7 are all leading ASSIGNMENTS, so
   sp consumes and substitutes them without my having to state a post at all.
   Three attempts at spelling that post out failed and sp removed the
   guessing.  (The note that used to sit here -- "os{2} = [] is genuinely not
   carried by the nest's invariant" -- was true when written and is now FALSE:
   os{2} = [] is carried by every nest and pk invariant.  Corrected rather than
   left, because a comment naming already-finished work as outstanding costs a
   future session exactly the time it claims to save.) *)
sp 1 7.
(* THE REMAINING ADMIT, scoped.  Three pieces, of which (1) is now CLOSED:

   (1) PK-LOOP ALIGNMENT -- DONE (leaves_eq_cube + pkfors_of_from_roots, see
       the per-instance body below).  Kept for the route it records:
       GprocVI.ec:39 `pkfors_of_from_roots` -- given roots that agree with
       FTWES.val_bt_trh over the honest leaf cube, the trco of the flattened
       roots IS pkfors_of skF ps ad, which is what keygen's gen_pkFORS
       produces.  So the only real obligation is that find's
         leaves_u = take t (drop (i*l'*k*t + j*k*t + u*t) leavess)
       equals fors_leaves_op_cube skF ps adT u -- i.e. the challenger's images
       ARE the honest leaves.  That follows from two facts the sampling nest
       already proved: ys0 = unzip2 ts, and ts[idx] = (tws[idx], f pp tws[idx]
       xs[idx]) with xs[idx] = val of the nested secret element.  Composing
       them gives ys0[idx] = f pp (leaf tweak) (val sk elem), which is the leaf.

   (2) THE FORGE CALL.  A `call` with the O_CMA equivalence: the reduction's
       oracle must be observationally equal to O_CMA_Gproc_I, differing only in
       that it serves each secret element via O.open instead of reading the
       stored key -- which is sound exactly because of (1)'s correspondence.
       This is where R_OPRE_Gproc.lidxs has to be tied to Gproc's end-of-game
       `flatten (map hC ts)` (see delta (4) in the header).

   (3) THE WIN CONDITION.  0 <= i < nrts, nrts <= l*k*t (FTWES.dval),
       !opened, dist, and f pp tw x = y.  `!opened` needs os{2} = [], and that
       is ALREADY CARRIED -- by every nest invariant and every pk invariant.
       (This paragraph used to say the opposite and name extending them as
       prerequisite work; it was true when written and went stale when the
       carry landed.) *)
(* PIECE (1): isolate the two pk loops.  A bare two-sided `while` is rejected
   here ("invalid last instruction") because the left continues past its loop
   into keygen's return, the oracle init and forge; the loops have to be
   seq'd off first.  The post only has to be PROVABLE by the loop -- the
   remainder is still admitted -- so it carries just what the loops establish
   PLUS what the per-instance body needs: ps0{1} = pp{2}, size ts{2}, the tws
   characterisation, and (inner only) the outer guard size pkFORSs{2} < nrts.
   Guards align because pkFORSnt0{1} = pkFORSs{2}, both against nr_trees 0. *)
seq 1 1 : (   ={glob A}
           /\ ps{1} = pp{2}
           /\ ps0{1} = pp{2}
           /\ ad{1} = adz
           /\ ad0{1} = adz
           /\ R_OPRE_Gproc.ad{2} = adz
           /\ R_OPRE_Gproc.ps{2} = pp{2}
           /\ pkFORSnt0{1} = pkFORSs{2}
           /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
              = nr_trees 0 * l' * k * SPHINCS_PLUS.t
           /\ size tws{2} = nr_trees 0 * l' * k * SPHINCS_PLUS.t
           /\ (forall (i1 j1 w1 : int), 0 <= i1 < nr_trees 0 => 0 <= j1 < l' =>
                 0 <= w1 < k * SPHINCS_PLUS.t =>
                 nth witness tws{2} (i1 * l' * k * SPHINCS_PLUS.t
                                     + j1 * k * SPHINCS_PLUS.t + w1)
                 = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                     i1) j1) 0 w1)
           /\ R_OPRE_Gproc.leavess{2}
              = unzip2 FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2} = []
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
           /\ R_OPRE_Gproc.lidxs{2} = []
           /\ (forall (idx : int),
                 0 <= idx < size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} =>
                 nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} idx
                 = (nth witness tws{2} idx,
                    f pp{2} (nth witness tws{2} idx)
                      (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2} idx)))
           /\ (forall (i j0 u0 v0 : int),
                 0 <= i < nr_trees 0 => 0 <= j0 < l' =>
                 0 <= u0 < k => 0 <= v0 < SPHINCS_PLUS.t =>
                 nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                   (i * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t
                    + u0 * SPHINCS_PLUS.t + v0)
                 = DigestBlock.val
                     (nth witness (nth witness (FTWES.DBLLKTL.val
                       (nth witness (nth witness skFORSnt0{1} i) j0)) u0) v0))).
+ while (   ={glob A}
           /\ ps{1} = pp{2}
           /\ ps0{1} = pp{2}
           /\ ad{1} = adz
           /\ ad0{1} = adz
           /\ R_OPRE_Gproc.ad{2} = adz
           /\ R_OPRE_Gproc.ps{2} = pp{2}
           /\ pkFORSnt0{1} = pkFORSs{2}
           /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
              = nr_trees 0 * l' * k * SPHINCS_PLUS.t
           /\ size tws{2} = nr_trees 0 * l' * k * SPHINCS_PLUS.t
           /\ (forall (i1 j1 w1 : int), 0 <= i1 < nr_trees 0 => 0 <= j1 < l' =>
                 0 <= w1 < k * SPHINCS_PLUS.t =>
                 nth witness tws{2} (i1 * l' * k * SPHINCS_PLUS.t
                                     + j1 * k * SPHINCS_PLUS.t + w1)
                 = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                     i1) j1) 0 w1)
           /\ R_OPRE_Gproc.leavess{2}
              = unzip2 FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2} = []
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
           /\ R_OPRE_Gproc.lidxs{2} = []
           /\ (forall (idx : int),
                 0 <= idx < size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} =>
                 nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} idx
                 = (nth witness tws{2} idx,
                    f pp{2} (nth witness tws{2} idx)
                      (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2} idx)))
           /\ (forall (i j0 u0 v0 : int),
                 0 <= i < nr_trees 0 => 0 <= j0 < l' =>
                 0 <= u0 < k => 0 <= v0 < SPHINCS_PLUS.t =>
                 nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                   (i * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t
                    + u0 * SPHINCS_PLUS.t + v0)
                 = DigestBlock.val
                     (nth witness (nth witness (FTWES.DBLLKTL.val
                       (nth witness (nth witness skFORSnt0{1} i) j0)) u0) v0))).
  - (* pk-loop BODY: wp absorbs the two trailing rcons, then the l' loops align
       on pkFORSlp{1} = pkFORSl{2}. *)
    wp => /=.
    while (   ={glob A}
           /\ ps{1} = pp{2}
           /\ ps0{1} = pp{2}
           /\ ad{1} = adz
           /\ ad0{1} = adz
           /\ R_OPRE_Gproc.ad{2} = adz
           /\ R_OPRE_Gproc.ps{2} = pp{2}
           /\ pkFORSnt0{1} = pkFORSs{2}
           /\ size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
              = nr_trees 0 * l' * k * SPHINCS_PLUS.t
           /\ size pkFORSs{2} < nr_trees 0
           /\ size tws{2} = nr_trees 0 * l' * k * SPHINCS_PLUS.t
           /\ (forall (i1 j1 w1 : int), 0 <= i1 < nr_trees 0 => 0 <= j1 < l' =>
                 0 <= w1 < k * SPHINCS_PLUS.t =>
                 nth witness tws{2} (i1 * l' * k * SPHINCS_PLUS.t
                                     + j1 * k * SPHINCS_PLUS.t + w1)
                 = set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype)
                     i1) j1) 0 w1)
           /\ pkFORSlp{1} = pkFORSl{2}
           /\ R_OPRE_Gproc.leavess{2}
              = unzip2 FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2} = []
           /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = pp{2}
           /\ R_OPRE_Gproc.lidxs{2} = []
           /\ (forall (idx : int),
                 0 <= idx < size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} =>
                 nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} idx
                 = (nth witness tws{2} idx,
                    f pp{2} (nth witness tws{2} idx)
                      (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2} idx)))
           /\ (forall (i j0 u0 v0 : int),
                 0 <= i < nr_trees 0 => 0 <= j0 < l' =>
                 0 <= u0 < k => 0 <= v0 < SPHINCS_PLUS.t =>
                 nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                   (i * l' * k * SPHINCS_PLUS.t + j0 * k * SPHINCS_PLUS.t
                    + u0 * SPHINCS_PLUS.t + v0)
                 = DigestBlock.val
                     (nth witness (nth witness (FTWES.DBLLKTL.val
                       (nth witness (nth witness skFORSnt0{1} i) j0)) u0) v0))).
    * (* PER-INSTANCE BODY.  BOTH sides have a certified bridge to the SAME
         normal form `pkfors_of skF ps adT`, so no hand computation is needed:
           LEFT   GprocFORSC10.ec:1110 `genpkfors_cf_op` --
                  phoare[gen_pkFORS : .. ==> res = pkfors_of skF ps0 ad0] = 1%r,
                  usable as call{1}.
           RIGHT  GprocVI.ec:39 `pkfors_of_from_roots` --
                  trco ps (set_kpidx (set_typeidx adT trcotype) (get_kpidx adT))
                       (flatten (map val roots)) = pkfors_of skF ps adT,
                  GIVEN size roots = k and
                    roots[u] = val_bt_trh ps adT
                                 (list2tree (fors_leaves_op_cube skF ps adT u)) u.

         So the ONE real obligation left in this body is that premise: find's
           leaves_u = take t (drop (i*l'*k*t + j*k*t + u*t) leavess)
         equals fors_leaves_op_cube skF ps adT u -- the challenger's images are
         the honest leaves.  It composes ys0 = unzip2 ts with ts[idx] =
         (tws[idx], f pp tws[idx] xs[idx]) and xs[idx] = val of the nested
         secret element, all three PROVED by the sampling nest.

         INPUTS: ALL PRESENT (this paragraph used to say the opposite, and was
         stale in BOTH directions -- re-checked against the invariants rather
         than believed).  The pk seq-1-1 post and both pk while-invariants now
         carry, verbatim: the anchors ps{1} = pp{2} / R_OPRE_Gproc.ps{2} = pp{2}
         / R_OPRE_Gproc.ad{2} = adz (without which `f pp` and `val_bt_trh ps`
         would be about different pubseeds, and adT would have no bridge to the
         tws tweak), leavess = unzip2 ts, os = [], the ts correspondence, the
         xs-is-the-secret-key correspondence, and the tws characterisation.

         INDEX AGREEMENT, VERIFIED AT SOURCE rather than by analogy -- this is
         the one the header flagged as SILENT, so it is checked before the
         composition is written, not after:
           fors_leaves_op_cube skF ps ad u
             = mkseq (fun v => f ps (set_thtbidx ad 0 (u*t + v))
                                 (val (nth (nth (DBLLKTL.val skF) u) v))) t
         (the honest leaf hashes at HEIGHT 0 and FLAT index u*t+v -- not at v
         under a per-tree set_tidx), and find assigns
           adT <- set_kpidx (set_tidx (set_typeidx ad trhftype)
                    (size pkFORSs)) (size pkFORSl)
         with ad = R_OPRE_Gproc.ad = adz.  Instantiating the carried tws fact
         at i1 = size pkFORSs, j1 = size pkFORSl, w1 = u*t+v therefore gives
         EXACTLY set_thtbidx adT 0 (u*t+v): same setter order, same trhftype,
         same height, same flat index.  The `0 <= u*t+v < k*t` side condition
         is flat_le SPHINCS_PLUS.t u k v, already proved above. *)
      (* Left is ONE call (gen_pkFORS); right is the roots loop then trco.  The
         right's loop is one-sided, so it needs a variant.

         `sp 1 2` FIRST, and this is a correctness fix rather than tidying.
         exists* abstracts a value out of the CURRENT precondition, so with the
         leading assignments still pending it captured skFORS{1} BEFORE
           skFORS <- nth (nth skFORSnt0 (size pkFORSnt0)) (size pkFORSlp),
         while the call's precondition asks about the value AFTER it.  The
         resulting obligation `nth (nth skFORSnt0 ..) .. = skFv` is then
         unprovable from `skFv = <stale skFORS{1}>`.  Nothing flagged it,
         because the discharge underneath was still an admit -- it only showed
         up in the goal dump.  Consuming both leading assignments first makes
         skFv the value the call actually receives. *)
      sp 1 2.
      wp.
      (* The roots loop must RECORD what it computes, or pkfors_of_from_roots'
         premise is unreachable later.  Stated in the raw take/drop form the
         loop actually produces; converting that to fors_leaves_op_cube is the
         separate leaves-equal-cube step. *)
      while{2} (   0 <= size roots{2} <= k
                /\ (forall (u : int), 0 <= u < size roots{2} =>
                      nth witness roots{2} u
                      = FTWES.val_bt_trh R_OPRE_Gproc.ps{2} adT{2}
                          (list2tree (take SPHINCS_PLUS.t
                             (drop (size pkFORSs{2} * l' * k * SPHINCS_PLUS.t
                                    + size pkFORSl{2} * k * SPHINCS_PLUS.t
                                    + u * SPHINCS_PLUS.t)
                                   R_OPRE_Gproc.leavess{2}))) u))
               (k - size roots{2}).
      + by move=> &m0 z; wp; skip => />;
           smt(size_rcons nth_rcons_lt nth_rcons_eq).
      (* Arguments read off a goal dump, not guessed: the left's call is
           gen_pkFORS(skFORS, ps0, set_kpidx (set_tidx (set_typeidx ad0 trhftype)
                                     (size pkFORSnt0)) (size pkFORSlp))
         with skFORS assigned from skFORSnt0 the statement before. *)
      (* The spec's arguments are LOGICAL values, so the program-state values
         have to be lifted first with exists*/elim* -- naming program variables
         directly fails ("unknown variable"), and holes fail ("cannot infer all
         placeholders"). *)
      exists* skFORS{1}, ps0{1},
              (set_kpidx (set_tidx (set_typeidx ad0{1} trhftype)
                 (size pkFORSnt0{1})) (size pkFORSlp{1})).
      elim* => skFv psv advv.
      call{1} (genpkfors_cf_op skFv psv advv).
      (* LEAVES-EQUAL-CUBE.  The tws characterisation this used to be blocked
         on is now carried all the way here, so the obligation composes:
           leavess = unzip2 ts        (the slice is over ts)
           ts[idx]  = (tws[idx], f pp tws[idx] xs[idx])
           tws[idx] = set_thtbidx adT 0 (u*t+v)     <- the pick/target agreement
           xs[idx]  = val skF[u][v]                 <- the reduction's point
         which is exactly leaves_eq_cube's premise list; pkfors_of_from_roots
         then turns the root list into pkfors_of. *)
      skip => &1 &2 hpre.
      (* The call's argument triple.  The post is `args && forall result, ..`
         and `&&` is EC's ASYMMETRIC and, so split leaves `args` and
         `args => forall result, ..` -- one extra antecedent to introduce.
         Dropping it silently shifted every later intro by one and the failure
         surfaced two tactics downstream, at a `split` that had nothing to
         split; the arity was measured, not guessed. *)
      split; first by smt().
      move=> _ result hres.
      (* roots-loop ENTRY: roots{2} = [], so the correspondence is vacuous *)
      split; first by smt(ge1_k).
      move=> roots_R; split; first by smt().
      move=> hne hrinv /=.
      (* Bridge the two namings.  psv/advv are the LEFT's call arguments; the
         roots loop speaks of R_OPRE_Gproc.ps{2}/adT{2}.  Both reduce to the
         same thing only because ps0{1} = pp{2} and the four address equalities
         hold -- ps0{1} = pp{2} was NOT carried by the pk invariants until this
         step, and without it psv and R_OPRE_Gproc.ps{2} are unrelated. *)
      have hps : R_OPRE_Gproc.ps{2} = psv by smt().
      have had : adT{2} = advv by smt().
      have hszr : size roots_R = k by smt().
      have hsl : size pkFORSl{2} < l' by smt().
      have hss : size pkFORSs{2} < nr_trees 0 by smt().
      have hcube : forall (u0 : int), 0 <= u0 < k =>
          nth witness roots_R u0
          = FTWES.val_bt_trh psv advv
              (list2tree (fors_leaves_op_cube skFv psv advv u0)) u0.
      + move=> u0 hu0.
        have hrn : nth witness roots_R u0
                 = FTWES.val_bt_trh R_OPRE_Gproc.ps{2} adT{2}
                     (list2tree (take SPHINCS_PLUS.t
                        (drop (size pkFORSs{2} * l' * k * SPHINCS_PLUS.t
                               + size pkFORSl{2} * k * SPHINCS_PLUS.t
                               + u0 * SPHINCS_PLUS.t)
                              R_OPRE_Gproc.leavess{2}))) u0 by smt().
        rewrite hrn hps had; congr; congr.
        (* the slice is over ts, via leavess = unzip2 ts *)
        have hlv : R_OPRE_Gproc.leavess{2}
                 = unzip2 FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2} by smt().
        rewrite hlv.
        (* THE FIT BOUND.  Three nested applications of flat_span, innermost
           first, each supplying the next one's `lo`.  Stated as a `have` and
           not left to smt: it is the four-factor telescope that cost five
           attempts one nest up. *)
        have hfit : size pkFORSs{2} * l' * k * SPHINCS_PLUS.t
                  + size pkFORSl{2} * k * SPHINCS_PLUS.t
                  + u0 * SPHINCS_PLUS.t + SPHINCS_PLUS.t
                  <= size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}.
        + have s3 := flat_span SPHINCS_PLUS.t u0 k SPHINCS_PLUS.t _ _ _ _;
            1..4: by smt(ge2_t).
          have s2 := flat_span (k * SPHINCS_PLUS.t) (size pkFORSl{2}) l'
                       (u0 * SPHINCS_PLUS.t + SPHINCS_PLUS.t) _ _ _ _;
            1..4: by smt(ge1_k ge2_t size_ge0).
          have s1 := flat_span (l' * k * SPHINCS_PLUS.t) (size pkFORSs{2})
                       (nr_trees 0)
                       (size pkFORSl{2} * k * SPHINCS_PLUS.t
                        + u0 * SPHINCS_PLUS.t + SPHINCS_PLUS.t) _ _ _ _;
            1..4: by smt(FTWES.ge1_l ge1_k ge2_t size_ge0).
          smt().
        apply (leaves_eq_cube _ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                 tws{2} _ _ _
                 (size pkFORSs{2} * l' * k * SPHINCS_PLUS.t
                  + size pkFORSl{2} * k * SPHINCS_PLUS.t) u0).
        - by smt().
        - by smt(size_ge0 mulr_ge0 FTWES.ge1_l ge1_k ge2_t).
        - by smt().
        - by smt().
        - (* the tweak, instantiated at w1 = u0*t + v *)
          move=> v hv.
          have := hrinv.
          have hb : 0 <= u0 * SPHINCS_PLUS.t + v < k * SPHINCS_PLUS.t.
          + by have := flat_le SPHINCS_PLUS.t u0 k v; smt(ge2_t).
          have htwx : nth witness tws{2}
                        (size pkFORSs{2} * l' * k * SPHINCS_PLUS.t
                         + size pkFORSl{2} * k * SPHINCS_PLUS.t
                         + (u0 * SPHINCS_PLUS.t + v))
                    = set_thtbidx (set_kpidx (set_tidx
                        (set_typeidx adz trhftype) (size pkFORSs{2}))
                        (size pkFORSl{2})) 0 (u0 * SPHINCS_PLUS.t + v)
            by smt(size_ge0).
          by rewrite -had /=; smt().
        - (* the preimage IS the secret-key element *)
          move=> v hv.
          have hxe : nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                       (size pkFORSs{2} * l' * k * SPHINCS_PLUS.t
                        + size pkFORSl{2} * k * SPHINCS_PLUS.t
                        + u0 * SPHINCS_PLUS.t + v)
                   = DigestBlock.val
                       (nth witness (nth witness (FTWES.DBLLKTL.val
                          (nth witness (nth witness skFORSnt0{1}
                             (size pkFORSs{2})) (size pkFORSl{2}))) u0) v)
            by smt(size_ge0).
          by rewrite hxe; smt().
      (* the certified trco bridge *)
      have hpk := pkfors_of_from_roots skFv psv advv roots_R hszr hcube.
      have hrc : rcons pkFORSlp{1} result
               = rcons pkFORSl{2}
                   (trco R_OPRE_Gproc.ps{2}
                      (set_kpidx (set_typeidx adT{2} trcotype)
                         (FTWES.get_kpidx adT{2}))
                      (flatten (map DigestBlock.val roots_R))).
      + by rewrite hps had hpk hres; congr; smt().
      by do! split; smt(size_rcons).
    by wp; skip; smt().
  (* OUTER pk ENTRY, grounded for the same reason the sampling nest's entry
     was: the pk invariants now carry the tws characterisation, and a one-line
     smt cannot re-establish a quantified equation over four nested address
     setters while also doing the size arithmetic.  All three depths are read
     off a dump, not counted by eye -- `sp 1 7` PREPENDS its eight assignment
     equations ahead of the nest post, so the premise carries the conjunct at
     18 while the invariant and the exit POST both want it at 11. *)
  skip => &1 &2 hpre.
  move: hpre => [p1 [p2 [p3 [p4 [p5 [p6 [p7 [p8 [p9 [p10 [p11 [p12 [p13 [p14
                [p15 [p16 [p17 [ptws prest]]]]]]]]]]]]]]]]]].
  split.
  + split; last by smt().
    do 10! (split; first by smt()).
    split; first by apply ptws.
    by do! split; smt().
  move=> pknL pksR g1 g2 hinv.
  move: hinv => [r1 [r2 [r3 [r4 [r5 [r6 [r7 [r8 [r9 [r10 [rtws rrest]]]]]]]]]]].
  do 10! (split; first by smt()).
  split; first by apply rtws.
  by do! split; smt().
(* ===========================================================================
   THE FORGE CALL AND THE WIN CONDITION -- THE LAST ADMIT, SCOPED FROM SOURCE.

   MM45's template is FORS_ES.ec:4452-4560 (and on).  Read, not guessed at; the
   shape below is theirs with the C10 deltas substituted.  Order of tactics:

     inline{2} 13; inline{2} 12; inline{2} 11;   (* opened / nr_targets / dist *)
     wp .. => /=;
     conseq (: _ ==> <left event> => <right win condition>);
     .. ; call (: <ORACLE INVARIANT>).

   (A) THE conseq.  The post is NOT an equality -- it is the implication
       "left event => right win", so the two sides need not agree on anything
       after the fork.  MM45's instance is
         is_fresh{1} /\ !valid_ITSR{1} /\ valid_OpenPRE{1}
         => 0 <= i{2} < d*k*t /\ !(i{2} \in os{2}) /\ f pp{2} tw{2} x{2} = y{2}.
       Ours substitutes `!EUF_CMA_Gproc_V.covered{1}` for `!valid_ITSR{1}`.

   (B) THE ORACLE INVARIANT, eight conjuncts in MM45, of which TWO change:
       - `={mmap}` and `dom mmap = mem qs` DROP OUT.  Gproc's O_CMA_Gproc_I
         does not memoise (delta (4) in this file's header), so there is no
         mmap on either side; the ghost `ts` list replaces it.
       - their `forall m, m \in mmap => all (mem lidxs) (g (mco .. m))` is
         replaced by the STRONGER and simpler
           R_OPRE_Gproc.lidxs{2}
           = flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2)
                          O_CMA_Gproc_I.ts{1})
         which holds because BOTH sides append on every call, with no miss
         test.  Note this is exactly EUF_CMA_Gproc_V's ghost `cov`, so it is
         also what ties `!covered` to the freshness of the chosen index.
       The remaining six carry over unchanged in substance: ps/ad agreement,
       pp = R_OPRE_Gproc.ps, the leavess characterisation, the xs-is-the-secret
       -key correspondence, size leavess, and -- the load-bearing one --
         forall idxs, idxs \in lidxs{2}
           <=> (ranges /\ flat(idxs) \in O_SMDTOpenPRE_Default.os{2})
       which is what makes `!opened` provable at the end.  os{2} = [] is
       carried INTO the call but is NOT preserved by it: every O.open appends.

   (C) WHAT IS ALREADY AVAILABLE, so the remaining work is smaller than MM45's:
       - `dist` is DONE: tws_uniq above, with tweak_getidx/flat_decomp.  This
         is MM45's longest single block (FORS_ES.ec:4465-4508) and it does not
         need to be redone.
       - the ap equality inside the signing loop is leaves_eq_cube, already
         proved and already used once in the pk body.
       - `f pp tw x = y` is exactly valid_OpenPRE: the left's
           leaf' = f ps (set_thtbidx adT 0 (dftidx*t+dflfidx)) (val x')
         against ts[cidx] = (tws[cidx], f pp tws[cidx] xs[cidx]) with
         tws[cidx] the same tweak and xs[cidx] = val skF[dftidx][dflfidx].
       - `0 <= i < nrts` and `nrts <= t_smdtopenpre` come from flat_decomp plus
         FTWES.dval (l = nr_trees 0 * l', so l*k*t is exactly size ts).

   So the open work is (i) the oracle equivalence, whose signing loop is the
   only genuinely new proof, and (ii) the freshness biconditional in (B).

   (D) THE ORACLE EQUIVALENCE BODY, aligned statement by statement.  Both sign
       procedures are in this file/GprocFORSC10 and were read off, not recalled:

         LEFT  O_CMA_Gproc_I.sign          RIGHT R_OPRE_Gproc(..).O_CMA.sign
         1 mk <$ dcond dmkey (good_fors m) 1 mk <$ dcond dmkey (good_fors m)
         2 ts <- rcons ts (mk, m)          2 lidxs <- lidxs ++ M.F.hC mk m
         3 (cm, idx) <- mco mk m           3 (cm, idx) <- mco mk m
         4 (tidx,kpidx) <- edivz .. l'     4 (tidx,kpidx) <- edivz .. l'
         5 skFORS <- sks[tidx][kpidx]      5 sigFORSTW <- []
         6 sigFORSTW <@ FL_..NPRF.sign(..) 6 while (size sigFORSTW < k) { .. }
         7 qs <- rcons qs m
       So 1 pairs by `rnd`, 2-4 by `sp`, and left 6 (inlined) against right 6.

       MM45'S `if (m \notin mmap)` BRANCH DROPS OUT ENTIRELY (FORS_ES.ec:2268).
       Ours draws and appends unconditionally, so there is no `if => //` and
       the loop invariant loses every mmap conjunct.  Our version is strictly
       simpler here, not merely different.

       AND THE INNER LEAVES LOOP DOES NOT NEED TO BE REDONE.  MM45 characterises
       gen_leaves_single_tree with an inline `while{1}` (FORS_ES.ec:4604-4612).
       We already have it CERTIFIED: FxChain.ec:729 `genleaves_cube_cf_h` is
       admit-free and FxChain is in closure-c10-split.txt, so it is usable as a
       `call{1}` exactly the way genpkfors_cf_op was used in the pk body above.
       CAUTION, checked: cdrafts-split/_gut.ec carries an ADMITTED copy of the
       same lemma name (that file has 38 admits and is not in the closure) --
       the FxChain one is the one to cite.
       With it, the loop body's `leaves` obligation is
         take t (drop base leavess) = fors_leaves_op_cube skF ps adT u,
       i.e. leaves_eq_cube, already proved.

       That leaves TWO genuinely new obligations in the loop body:
         - the secret element: left reads skFORS[u][lidx] as a dgstblock while
           right gets O.open(base+lidx) : dgst and re-embeds with
           DigestBlock.insubd, so it is the xs-correspondence composed with
           DigestBlock.valKd;
         - maintaining the lidxs <-> os biconditional across the O.open, which
           is the only place os grows.

   UPDATE 2026-08-09.  (i) IS DONE.  Eqv_OCMA_sign is proved -- entry, body and
   exit -- and the forge call below CONSUMES it via `conseq (Eqv_OCMA_sign A)`,
   so what (D) called "the only genuinely new proof" is closed.  What is left is
   the WIN CONDITION, and the dump of it decomposes into exactly five targets.
   Writing them down with the fact each one runs on, because every ingredient is
   already proved in this file and the risk now is losing track of that:

     let H  = M.F.hC mk' m',  cov = flatten (map hC ts_L),
         E  = nth witness H (find (fun x => ! (x \in cov)) H),
         CIDX = val idx' %/ l' * l'*k*t + val idx' %% l' * k*t + E.`2*t + E.`3

     T1  0 <= CIDX < size ts{2}
         <- find_fresh (E is a real element of H) + hC_range + hC_fst + the
            flat_span/flat_decomp arithmetic already used for the leaves cube.
     T2  0 <= size ts{2} <= l*k*t
         <- the carried `size ts{2} = nr_trees 0 * l'*k*t` and nr_trees0_l.
     T3  ! (CIDX \in os_R)
         <- THE COVERAGE BICONDITIONAL.  find_fresh gives E \notin cov, and the
            invariant gives cov = lidxs_R, so E \notin lidxs_R; the biconditional
            then says NOT(ranges /\ flat E \in os_R), and hC_range supplies the
            ranges, leaving flat E \notin os_R.  This is the conjunct the whole
            invariant strengthening existed for.
     T4  uniq (unzip1 ts{2})
         <- tws_uniq, already proved, plus `unzip1 ts{2} = tws{2}` from the ts
            characterisation.
     T5  f pp{2} (ts{2}[CIDX]).`1 (val x') = (ts{2}[CIDX]).`2
         <- valid_OpenPRE{1}, plus the ts characterisation (ts{2}[CIDX] =
            (tws{2}[CIDX], f pp tws{2}[CIDX] xs{2}[CIDX])), the tws
            characterisation to identify the tweaks, and the leaves/xs
            characterisations to identify the leaf.
            T5 IS THE ONE ENTRY HERE NOT FULLY READ OFF THE DUMP -- flagged
            rather than left to be discovered mid-discharge.  What IS confirmed
            from the dumped text: the antecedent's last conjunct is an equation
              f ps{1} (set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{1}
                        trhftype) (E.`1 %/ l')) (E.`1 %% l')) 0 (..)) (val x')
              = <leaf op> skF ps{1} adT E.`2 E.`3
            and that `wp => /=` has ALREADY unfolded the cube, so the goal does
            NOT literally contain fors_leaves_op_cube.  Consequence: whether
            leaves_eq_cube is needed at all, or the leaves/xs characterisations
            apply directly to the unfolded form, is OPEN.  Settle it from a full
            dump of this goal before relying on this line.
            is_valid{1} and is_fresh{1} are NOT used anywhere in T1-T5 -- which
            is why pkFORS_from_sigFORSTW only has to be lossless.

   UPDATE 2026-08-10, and this entry RETRACTS the two before it.  External
   review (GPT-5.6, read-only over this repo) found the premise wrong, and its
   two load-bearing citations were checked against the dump by hand before this
   was written.

   WHAT I CLAIMED, TWICE: that T1, T4 and T5 are UNPROVABLE because `size ts`,
   `uniq (unzip1 ts)` and the ts/tws characterisations are not in the oracle
   invariant, and that the fix is to thread four conjuncts through
   Eqv_OCMA_sign's pre, post and loop invariant.

   WHY IT IS WRONG: "not in I" does NOT mean "forgotten".  `call (: I)` leaves a
   single `skip` goal whose hypothesis is the PRE, and whose continuation
   quantifies ONLY what the call may write.  Read off the dump, that
   continuation binds exactly eight things --
     result_L result_R A_L qs_L ts_L A_R lidxs_R os_R
   -- and NONE of them is O_SMDTOpenPRE_Default.ts, .xs, or the caller-local
   tws.  Left sign writes O_CMA_Gproc_I.ts/qs, right sign writes
   R_OPRE_Gproc.lidxs, and O.open writes only os (TweakableHashFunctions.eca
   :197 -- it READS xs).  So hszts, hsztws, htwsc, htsc and hxsc are all still
   in context after the call, BY FRAMING.  MM45 does the same thing: its call
   invariant omits the target-ts facts (FORS_ES.ec:4525) and it still uses
   nthxs/nthts/szts afterwards (:4780, :4823).

   CONSEQUENCE: NO THREADING.  Leave Eqv_OCMA_sign alone -- its digest does not
   move a second time, and the peeled body/entry/exit discharges stay intact.
   Discharge T1-T5 directly from the named pre hypotheses plus the nine
   invariant conjuncts the call delivers:
     T1  hszts + hC_fst/hC_range + edivz bounds + flat_idx_ge0/flat_idx_lt
     T2  hszts + nr_trees0_l
     T3  find_fresh + hC_range + the coverage biconditional   (unchanged)
     T4  derive `unzip1 ts = tws` extensionally (eq_from_nth) from hszts,
         hsztws and htsc's first projection, then tws_uniq
     T5  htsc at CIDX, htwsc for the tweak, hxsc for the secret value
   Tactic note from the same review: establish and NAME `0 <= CIDX < size ts`
   BEFORE splitting T1-T5 -- proving it inside the T1 branch does not make it a
   hypothesis in the T5 branch.

   AND T5 DOES NOT NEED leaves_eq_cube, but not for the reason I gave.  My
   earlier claim that `wp => /=` had unfolded the cube is FALSE: the saved goal
   literally contains fors_leaves_op_cube (verified by hand in the dump).  The
   route is cube_is_mkseq (GprocVI.ec:26) then nth_mkseq at 0 <= E.`3 < t, then
   hxsc and htwsc.  leaves_eq_cube proves a whole take/drop slice and is not
   what this needs; the leavess characterisation is not needed either.

   ONE OPEN ITEM, from the SECOND reviewer (Kimi K3, run independently on the
   same question; it converged with GPT-5.6 on the retraction above and then
   found this, which the first reviewer did not).  THE sk BRIDGE.  T5 must
   identify xs[CIDX] -- which the xs characterisation expresses over
   skFORSnt0{1} -- with the leaf's secret element, which valid_OpenPRE computes
   over skFORSnt{1}.  CHECKED BY HAND IN THE DUMP, and the two names really are
   different: the win condition's leaf op reads `nth witness skFORSnt{1}` while
   every xs-characterisation conjunct of the pre reads `skFORSnt0{1}`.
   The bridge is left statement 1, `(pkFORSnt, skFORSnt) <- (pkFORSnt0,
   skFORSnt0)`, which sits BEFORE the forge call -- so whether it survives into
   the continuation is precisely the open question, and it is the one thing that
   could still make T5 fail after everything above is right.
   SETTLED 2026-08-10, NEGATIVE -- no bridge is needed.  The admit branch was
   dumped (clean, 0 diagnostics) and searched: `skFORSnt0{1}` occurs four times
   and `skFORSnt{1}` NOT ONCE.  One occurrence is the pre's xs characterisation
   (hypothesis side) and the other three are in the goal, including the leaf op
   of valid_OpenPRE -- so both sides already speak of the SAME name.
   `inline{1} 2; wp` substitutes left statement 1 through, which is exactly
   what makes the bridge unnecessary rather than missing.  The two names in the
   EARLIER dump were an artefact of taking that dump at a different point in
   the proof, before the entry discharge was in place.
   So T5 has no fifth hole, and neither does anything else: the plan is the
   T1-T5 derivation listed above, discharged from the named pre hypotheses,
   with NO threading round and NO change to Eqv_OCMA_sign.

   THE INTRO PATTERN FOR THIS BRANCH, read off the same dump so the next cycle
   does not have to pay for another one.  `&&` is asymmetric, so branch 2 of the
   `split` carries branch 1 (the whole ENTRY conjunction) as its FIRST
   hypothesis -- discard it -- and only then come the binders:

     move=> _ rL rR AL qsL tsL AR lidxsR osR.
     move=> [hres [hgA [hpsR [hadR [had2R [hppR [hlidR
             [hLV [hXS [hCOV hszlv]]]]]]]]]].
     move=> result [[[[hpredc hpkr] hfresh] hncov] hvop].

   That is 8 binders, an 11-conjunct INV-after, then four `let`s (m'_R, sig'_R,
   m'_L, sig'_L), then `result : pkFORS`, then the antecedent nested as
   (((predC /\ pkr) /\ fresh) /\ ncov) /\ valid_OpenPRE.

   RETRACTED 2026-08-10 (second): the diagnosis recorded here yesterday was
   WRONG, and it is retracted at the line a reader would trust it.  I wrote
   that the failure of
     move=> result [[[hpredc hpkr] hfresh] hncov] hvop.
   with `invalid intro-pattern: nothing to eliminate` meant the antecedent had
   to be ONE bracket rather than two.  The bracket arity was never the problem.
   The real cause is that the four `let`s are INTROS: `move=> result` binds
   `result := result_R.`1`, the LET, and the following pattern then meets
   `let sig'_R = .. in`, which is not a conjunction -- hence the error, at the
   bracket's columns, which is what misled me.  `split`/`case` do NOT push
   through the lets either; that clause above was wrong too.
   MEASURED, not inferred: scratch/_letprobe{,2,3}.ec reproduce the exact error
   in 30 lines and show the two forms that work -- name the four lets
   (`move=> mR sR mL sL result [..]`), or `simplify` first (full delta, avoided
   here).  Same probe measured that `rewrite /mR` unfolds a let-introduced
   local, which is what the discharge below relies on.  The working script is
   at the `admit` site, not here; this entry exists only so the wrong
   diagnosis does not outlive itself.

   The 17 named pre hypotheses (hga hps hps0 hadL had0 had2 hpps hpk hszts
   hsztws htwsc hlvs hos hppg hlid htsc hxsc) are ALL still in scope here --
   that is the framing point above, and it is what T1/T4/T5 run on. *)

(* ---- SKELETON.  `is_valid{1}` and `is_fresh{1}` are NOT needed: every one of
   the five right-hand win conditions follows from `!covered{1}` and
   `valid_OpenPRE{1}` alone.  That is what lets pkFORS_from_sigFORSTW be
   discharged LOSSLESSLY with GprocFORSC10's pkfromsig_ll instead of
   characterised -- the alternative, FORSC10_Wire's pkfromsig_cf, is not in the
   certified closure and would have pulled an uncertified file into the cone. *)
inline{2} 13; inline{2} 12; inline{2} 11; inline{2} 10.
inline{1} 9.
wp => /=.
call{1} pkfromsig_ll.
wp => /=.
call (:   O_CMA_Gproc_I.ps{1} = R_OPRE_Gproc.ps{2}
       /\ O_CMA_Gproc_I.ad{1} = adz
       /\ R_OPRE_Gproc.ad{2} = adz
       /\ FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2} = R_OPRE_Gproc.ps{2}
       /\ R_OPRE_Gproc.lidxs{2}
          = flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2)
                         O_CMA_Gproc_I.ts{1})
       /\ (forall (i j u v : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
             0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
             nth witness R_OPRE_Gproc.leavess{2}
               (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                + u * SPHINCS_PLUS.t + v)
             = f FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.pp{2}
                 (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
                    0 (u * SPHINCS_PLUS.t + v))
                 (nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
                   (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                    + u * SPHINCS_PLUS.t + v)))
       /\ (forall (i j u v : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
             0 <= u < k => 0 <= v < SPHINCS_PLUS.t =>
             nth witness FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.xs{2}
               (i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                + u * SPHINCS_PLUS.t + v)
             = DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val
                 (nth witness (nth witness O_CMA_Gproc_I.sks{1} i) j)) u) v))
       /\ (forall (idxs : int * int * int),
             idxs \in R_OPRE_Gproc.lidxs{2}
             <=> (0 <= idxs.`1 < l /\ 0 <= idxs.`2 < k
                  /\ 0 <= idxs.`3 < SPHINCS_PLUS.t
                  /\ idxs.`1 %/ l' * l' * k * SPHINCS_PLUS.t
                     + idxs.`1 %% l' * k * SPHINCS_PLUS.t
                     + idxs.`2 * SPHINCS_PLUS.t + idxs.`3
                     \in FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.os{2}))
       /\ size R_OPRE_Gproc.leavess{2}
          = nr_trees 0 * l' * k * SPHINCS_PLUS.t).
+ by conseq (Eqv_OCMA_sign A).
inline{1} 2.
wp; skip => &1 &2 hpre.
(* Arity 17 and the conjunct ORDER are read off a cli dump.  Note hpps and hppg
   are DIFFERENT facts: the pre speaks of the LOCAL `pp{2}`, the invariant of
   the GLOBAL O_SMDTOpenPRE_Default.pp{2}, and the equation between them had to
   be threaded here -- third instance of the same missing-plumbing class, after
   the exit-vs-os one and lidxs = []. *)
move: hpre => [hga [hps [hps0 [hadL [had0 [had2 [hpps [hpk [hszts [hsztws
               [htwsc [hlvs [hos [hppg [hlid [htsc hxsc]]]]]]]]]]]]]]]].
split.
+ split; first by rewrite hpk hps hpps hadL had2.
  split; first by exact hga.
  split; first by rewrite hps hpps.
  split; first by exact hadL.
  split; first by exact had2.
  split; first by rewrite hppg hpps.
  split; first by rewrite hlid.
  split.
  - (* LEAVES: `leavess = unzip2 ts` meets the ts and tws characterisations. *)
    move=> i j u v hi hj hu hv.
    have hb0 : 0 <= i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
                    + u * SPHINCS_PLUS.t + v
      by apply flat_idx_ge0; smt().
    have hb1 : i * l' * k * SPHINCS_PLUS.t + j * k * SPHINCS_PLUS.t
               + u * SPHINCS_PLUS.t + v
             < size FTWES.F_OpenPRE.O_SMDTOpenPRE_Default.ts{2}.
    * rewrite hszts.
      have h := flat_idx_lt i j u v (nr_trees 0) 0 0 0 _ _ _ _ _ _ _;
        1..7: by smt().
      smt().
    have htw := htwsc i j (u * SPHINCS_PLUS.t + v) _ _ _; 1..3: by smt(ge2_t).
    rewrite hppg hlvs.
    rewrite (nth_map witness witness); 1: by smt().
    rewrite htsc; 1: by smt().
    by rewrite /=; congr; rewrite -htw; congr; ring.
  split; first by exact hxsc.
  split; first by move=> idxs; rewrite hlid hos.
  by rewrite hlvs size_map hszts.
(* ---- BRANCH 2: THE WIN CONDITION.  Everything substantive is in t1_win
   above; what is left here is plumbing, and each line of it is a fact that was
   MEASURED rather than guessed.

   (a) THE LEADING `_`.  `&&` is asymmetric, so this branch carries branch 1
       -- the whole ENTRY conjunction -- as its first hypothesis.  Discard it.

   (b) THE FOUR `let`s ARE INTROS, NOT PUNCTUATION.  This is what cost the
       previous cycle, and the note that stood here blamed the wrong thing:
       `move=> result` on a goal that opens `let m'_R = .. in` introduces the
       LET, binding `result := result_R.`1`, and the next pattern then faces
       `let sig'_R = .. in` and answers `invalid intro-pattern: nothing to
       eliminate`.  I read that error as an arity bug in the antecedent bracket
       and recorded it as such; it was not.  Measured in a 30-line probe
       (scratch/_letprobe{,2,3}.ec, kept): the bracket was always right, and
       the fix is to NAME the four lets.  `simplify` also works and is what
       MM45-style scripts do, but it is full delta on a goal this size, so the
       named-let form is preferred here.

   (c) WHY `rewrite hres` COMES FIRST.  m'_L/sig'_L and m'_R/sig'_R are
       DIFFERENT local definitions -- unfolding them is not enough to make the
       two sides syntactically equal.  Rewriting result_L into result_R BEFORE
       the lets are introduced makes all four bodies the same term, and then
       `rewrite /mL /sL` and `rewrite /mR /sR` land on identical text.  (That
       `rewrite /x` unfolds a let-introduced local at all is measured too --
       toyG in _letprobe3.ec.)

   (d) THE THREE REWRITES INTO hvop are the left-to-right dictionary: hps
       carries ps{1} to pp{2} (the pseed t1_win's htsc names), hadL carries
       ad{1} to adz, and -hlidR carries the `flatten (map hC ts_L)` coverage
       list to lidxs_R, which is the one the goal's `find` is stated over.

   (e) The residual goal after the apply is hEdef -- `E = nth .. (find ..)` --
       which is reflexivity once unification has read E off the conclusion. *)
move=> _ rL rR AL qsL tsL AR lidxsR osR.
move=> [hres [hgA [hpsR [hadR [had2R [hppR [hlidR
        [hLV [hXS [hCOV hszlv]]]]]]]]]].
rewrite hres.
move=> mR sR mL sL result [[[[hpredc hpkr] hfresh] hncov] hvop].
rewrite /mR /sR.
rewrite /mL /sL -hlidR in hncov.
rewrite /mL /sL hps hadL -hlidR in hvop.
apply (t1_win _ _ _ _ _ _ _ _ _ _ _
         hszts hsztws htwsc htsc hxsc hCOV hncov hvop).
by [].
qed.
