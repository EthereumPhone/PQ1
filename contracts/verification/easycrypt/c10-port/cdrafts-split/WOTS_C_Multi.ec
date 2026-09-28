(* ==========================================================================
   WOTS_C_Multi.ec  --  Thm D.1: MULTI-instance WOTS+C d-EU-naCMA.

   The multi-instance lift of Thm C.2 (single-instance, WOTS_C_Reduction.ec).
   The paper's App-D bound is the multi-instance analogue of C.2's two-term
   bound:

     InSec^{d-EU-naCMA}(WOTS+C ; t, d)
        <  InSec^{S-TCR(+C)}(Th+C ; ~t, d)          (* the ONE added +C term *)
         + InSec^{d-EU-naCMA}(WOTS-TW ; ~t, d).      (* MM45 machinery, UNCHANGED *)

   ------------------------------------------------------------------------
   MODELING (faithful to C.2, made explicit):

   * We work over the S-TCR(+C) collection `STCRC_WC.Col` (the Th_lambda that
     computes Th+C), EXACTLY as C.2's hop2 modeled WOTS-TW over `STCRC_WC.Col`
     rather than the repo's chain-hash-only collection `FC` (WOTS_TW_ES.ec:450,
     `in_t <- dgst`, `f <- f`).  The connection to the repo's FC-based
     `M_EUF_GCMA_WOTSTWESNPRF` (and thus to MM45's `MEUFGCMA_WOTSTWESNPRF`
     black box) is the FC <-> STCRC_WC.Col unification deferred already in C.2
     (WOTS_C_Reduction.ec:344, which calls it "the remaining structural
     reconciliation").  IT IS NOT DISCHARGED, AND IT IS NOT IN THIS FILE.

     CORRECTED 2026-08-18.  The sentence that stood here read "stated here as
     two clearly-labelled bridge admits, NOT smuggled into a module we cannot
     write".  Every part of that is wrong about the present tree, and the
     correction is recorded rather than quietly applied because a reader must
     not believe a bridge exists here:
       (i)   THIS FILE HAS NO ADMITS AT ALL.  scratch/sweep.py (comment-
             stripping, word-boundary) reports admit=0 axiom=0 sorry=0, so
             nothing here is labelled as, or stands in for, the bridge.
       (ii)  The two artefacts the older text meant are LEMMAS, not admits, and
             they live DOWNSTREAM rather than here: `D1_bridge_WOTSTW`
             (WOTS_C_Bridge.ec:391) and `D1_MEUFNACMA_WOTSC_MM45`
             (WOTS_C_Bridge.ec:677), the latter specialised as
             `D1_MEUFNACMA_WOTSC_MM45_embthfc` (WOTS_C_EmbDischarge.ec:174) and
             consumed at SPHINCS_C.ec:252.  WOTS_C_Bridge.ec REQUIRES this file
             (its :137), so it could never be "below" inside it.
       (iii) NONE of WOTS_C_Bridge.ec, WOTS_C_EmbDischarge.ec, SPHINCS_C.ec is
             in closure-c10-split.txt, so nothing in them is gate-enforced.
       (iv)  MEASURED 2026-08-18 in the gate's own container (r2026.02, same
             include path, in the same run in which THIS file compiled RC=0):
             `easycrypt compile cdrafts-split/WOTS_C_Bridge.ec` EXITS 1 with
             `[critical] .. line 659 .. cannot prove goal (strict)` -- a step
             INSIDE `D1_bridge_WOTSTW`'s own proof (lemma :391, qed :665),
             reproduced twice at the same site --
             even though that file's header claims "PROOF STATUS (2026-07-08):
             PROVED IN FULL -- ZERO admits".  Whether that is a genuine break or
             a prover-budget artefact is NOT diagnosed here; either way it is
             not something a reader of THIS file may assume works.
     So the honest status is: the reconciliation is deferred here, attempted
     downstream in an UNGATED file, and at this toolchain that attempt does not
     compile.  D.1 below is therefore stated against the LOCAL WOTS-TW game
     `M_EUF_NACMA_WOTSTW_L`, and nothing in this file carries it to MM45's.

   * We model d-EU-naCMA in its literal non-adaptive shape: the adversary
     COMMITS its d signing queries in `choose()` (a `qC list`) and receives all
     d keypairs + signatures in `forge(ps, ks)`.  This is what lets BOTH
     reductions be REAL, zero-admit modules that DEFER signature construction to
     the point where the public seed is available (`find(pp)` / `forge(ps,_)`) —
     the exact idiom C.2's single-query `R_STCRC_WOTSC` / `R_WOTSTW_WOTSC` use,
     lifted to d queries.  (An adaptive-oracle M_EUF_GCMA shape would force the
     S-TCR reduction to reconstruct chain-hash `f` evaluations at the hidden pp
     during `choose`, which STCRC_WC.Col does not provide — precisely the
     unification above.  Non-adaptive commitment sidesteps it, and d-EU-naCMA is
     the notion Thm D.1 is stated for.)
   ========================================================================== *)

require import AllCore List Distr.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme WOTS_C_Reduction.

import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import WOTS_C_Scheme.
import WOTS_C_Reduction.

(* A single committed non-adaptive signing query: (WOTS address, message). *)
type qC = wadrs * dgstblock.

(* ROUTE (D): the +C game commits a NODE (`qC`); the WOTS-TW game commits the
   WIDE digest that ThC compresses it to (`qTW`).  Pre-split these were the same
   type and one `qC` served both -- WOTS_C_Multi.ec:293 said so explicitly.
   They are now genuinely different and must not be conflated. *)
type qTW = wadrs * msgWOTS.

(* ==========================================================================
   The multi-instance d-EU-naCMA game for WOTS+C  (LHS of Thm D.1).
   Non-adaptive: A commits a list of queries, then forges for one instance.
   ========================================================================== *)
module type Adv_MnaCMA_WOTSC(OC : STCRC_WC.Col.Oracle_THFC) = {
  proc choose() : qC list { OC.query }
  proc forge(ps : pseed, ks : (pkWOTS * (sigWOTS * cntr)) list)
       : int * dgstblock * (sigWOTS * cntr) {}
}.

module M_EUF_NACMA_WOTSC_L(A : Adv_MnaCMA_WOTSC, OC : STCRC_WC.Col.Oracle_THFC) = {
  module AA = A(OC)

  proc main() : bool = {
    var ps : pseed;
    var qs : qC list;
    var ks : (pkWOTS * (sigWOTS * cntr)) list;
    var adlO, adlOC : adrs list;
    var wad : wadrs;
    var m, m' : dgstblock;
    var pk : pkWOTSTW;
    var sk : skWOTS * pseed * adrs;
    var sigc, sigc' : sigWOTS * cntr;
    var i, k : int;
    var is_valid, is_fresh, dist_wgpidxs : bool;
    var nrqs : int;

    ps <$ dpseed;
    OC.init(ps);

    qs <@ AA.choose();

    (* Build every committed instance's keypair + honest WOTS+C signature. *)
    ks <- []; adlO <- []; k <- 0;
    while (k < size qs) {
      wad <- (nth witness qs k).`1;
      m   <- (nth witness qs k).`2;
      (pk, sk) <@ WOTS_C_ES.keygen(ps, WAddress.val wad);
      sigc <@ WOTS_C_ES.sign(sk, m);
      ks   <- rcons ks (pk.`1, sigc);
      adlO <- rcons adlO (WAddress.val wad);
      k <- k + 1;
    }

    (i, m', sigc') <@ AA.forge(ps, ks);

    wad <- (nth witness qs i).`1;
    m   <- (nth witness qs i).`2;
    is_valid <@ WOTS_C_ES.verify(((nth witness ks i).`1, ps, WAddress.val wad), m', sigc');
    is_fresh <- m' <> m;

    nrqs <- size qs;
    dist_wgpidxs <- uniq_wgpidxs adlO;
    adlOC <@ OC.get_tweaks();

    return 0 <= nrqs <= c /\ 0 <= i < nrqs /\
           is_valid /\ is_fresh /\ dist_wgpidxs /\ disj_wgpidxs adlO adlOC;
  }
}.

(* ==========================================================================
   The multi-instance d-EU-naCMA game for WOTS-TW, local to STCRC_WC.Col
   (the RHS WOTS-TW term of Thm D.1).  Same non-adaptive shape, over the REAL
   `WOTS_TW_ES_NPRF` scheme; signatures carry NO counter.  The bridge to the
   repo's FC-based `M_EUF_GCMA_WOTSTWESNPRF` IS NOT IN THIS FILE and is not an
   admit anywhere in it (CORRECTED 2026-08-18: this line read "is a labelled
   admit (below)"; the file carries admit=0 axiom=0 sorry=0).  See the header
   for where the bridge is attempted, and for its measured status there.
   ========================================================================== *)
module type Adv_MnaCMA_WOTSTW(OC : STCRC_WC.Col.Oracle_THFC) = {
  proc choose() : qTW list { OC.query }
  proc forge(ps : pseed, ks : (pkWOTS * sigWOTS) list)
       : int * msgWOTS * sigWOTS {}
}.

module M_EUF_NACMA_WOTSTW_L(A : Adv_MnaCMA_WOTSTW, OC : STCRC_WC.Col.Oracle_THFC) = {
  module AA = A(OC)

  proc main() : bool = {
    var ps : pseed;
    var qs : qTW list;
    var ks : (pkWOTS * sigWOTS) list;
    var adlO, adlOC : adrs list;
    var wad : wadrs;
    var m, m' : msgWOTS;
    var pk : pkWOTSTW;
    var sk : skWOTS * pseed * adrs;
    var sig, sig' : sigWOTS;
    var i, k : int;
    var is_valid, is_fresh, dist_wgpidxs : bool;
    var nrqs : int;

    ps <$ dpseed;
    OC.init(ps);

    qs <@ AA.choose();

    ks <- []; adlO <- []; k <- 0;
    while (k < size qs) {
      wad <- (nth witness qs k).`1;
      m   <- (nth witness qs k).`2;
      (pk, sk) <@ WOTS_TW_ES_NPRF.keygen(ps, WAddress.val wad);
      sig <@ WOTS_TW_ES_NPRF.sign(sk, m);
      ks   <- rcons ks (pk.`1, sig);
      adlO <- rcons adlO (WAddress.val wad);
      k <- k + 1;
    }

    (i, m', sig') <@ AA.forge(ps, ks);

    wad <- (nth witness qs i).`1;
    m   <- (nth witness qs i).`2;
    is_valid <@ WOTS_TW_ES_NPRF.verify(((nth witness ks i).`1, ps, WAddress.val wad), m', sig');
    is_fresh <- m' <> m;

    nrqs <- size qs;
    dist_wgpidxs <- uniq_wgpidxs adlO;
    adlOC <@ OC.get_tweaks();   (* kept: couples with GAME1_MULTI's get_tweaks in hop2 *)

    (* SOUNDNESS FIX 2026-07-08 — the WOTS-TW term game carries NO
       `disj_wgpidxs adlO adlOC` conjunct, matching C.2's single-instance
       `EUF_NACMA_WOTSTW` (WOTS_C_Reduction.ec:372 = `return m' <> m /\ is_valid`,
       disjointness-free).  An earlier draft MIS-COPIED that conjunct from the LHS
       `M_EUF_NACMA_WOTSC_L`; but the Alg-10 reduction `R_multi_WOTSTW.choose` MUST
       grind via OC at the instance addresses `WAddress.val wad` (pp is naCMA-hidden),
       so `adlO ⊆ adlOC` and the conjunct is IDENTICALLY FALSE for nrqs>=1 — which
       made this game vacuously 0 and hop2 (`Pr[GAME1_MULTI] <= Pr[this]`) FALSE,
       silently collapsing the headline to `Pr[LHS] <= Pr[S_TCR]`.  Dropping it makes
       the RHS the GENUINE WOTS-TW naCMA advantage = the true d-query lift of C.2's
       proven hop2.  `uniq_wgpidxs adlO` (multi-instance distinctness) is retained.
       ⚠ BRIDGE DEBT: this game is now disjointness-FREE ⇒ it has the LARGER winning
       set, so for a FIXED adversary `Pr[..._L(B)] >= Pr[MEUFGCMA_WOTSTWESNPRF(...)]`.
       The future MM45 bridge therefore must NOT be a standalone arbitrary-adversary
       `..._L(B) <= MEUFGCMA_WOTSTWESNPRF` (false same-direction); prove it for the
       COMPOSED adversary `R_multi_WOTSTW(A0)` carrying the SOURCE game's disj
       constraint, or restructure with MM45's O/OC separation. *)
    return 0 <= nrqs <= c /\ 0 <= i < nrqs /\
           is_valid /\ is_fresh /\ dist_wgpidxs;
  }
}.

(* ==========================================================================
   R_multi_STCRC — the multi-instance S-TCR(+C) reduction (Algorithm 9, lifted).
   The exact d-query lift of C.2's single-query `R_STCRC_WOTSC`
   (WOTS_C_Reduction.ec:65): it drives the WOTS+C forger A, registers ONE
   S-TCR(+C) target per committed query (so the k-th instance's honest counter
   equals the k-th recorded target counter — both are the deterministic grind),
   defers keypair/signature construction to `find(pp)` where the public seed is
   revealed, and relays A's forgery on instance i as the collision on target i.
   REAL module, zero admit.
   ========================================================================== *)
module (R_multi_STCRC (A : Adv_MnaCMA_WOTSC) : STCRC_WC.Adv_STCRC)
       (O : STCRC_WC.Oracle_STCRC, OC : STCRC_WC.Col.Oracle_THFC) = {
  module AA = A(OC)
  var qs : qC list

  (* Register a Prop-satisfying S-TCR(+C) target for every committed query. *)
  proc pick() : unit = {
    var k : int;
    var wad : wadrs;
    var m : dgstblock;
    var y : msgWOTS;   (* STCRC_WC out_t = ThC codomain *)
    var j : cntr;

    qs <@ AA.choose();
    k <- 0;
    while (k < size qs) {
      wad <- (nth witness qs k).`1;
      m   <- (nth witness qs k).`2;
      (y, j) <@ O.query(WAddress.val wad, m);
      k <- k + 1;
    }
  }

  (* With pp revealed, build every keypair + honest WOTS+C signature (the sign
     reproduces the recorded target counter since grind is deterministic), hand
     them to A, and relay A's forgery on instance i as the S-TCR(+C) collision. *)
  proc find(pp : pseed) : int * dgstblock * cntr = {
    var k : int;
    var wad : wadrs;
    var m, m' : dgstblock;
    var pk : pkWOTSTW;
    var sk : skWOTS * pseed * adrs;
    var sigc, sigc' : sigWOTS * cntr;
    var ks : (pkWOTS * (sigWOTS * cntr)) list;
    var i : int;

    ks <- []; k <- 0;
    while (k < size qs) {
      wad <- (nth witness qs k).`1;
      m   <- (nth witness qs k).`2;
      (pk, sk) <@ WOTS_C_ES.keygen(pp, WAddress.val wad);
      sigc <@ WOTS_C_ES.sign(sk, m);
      ks   <- rcons ks (pk.`1, sigc);
      k <- k + 1;
    }

    (i, m', sigc') <@ AA.forge(pp, ks);

    return (i, m', sigc'.`2);
  }
}.

(* ==========================================================================
   R_multi_WOTSTW — the multi-instance WOTS-TW reduction (Algorithm 10, lifted).
   The d-query lift of C.2's `R_WOTSTW_WOTSC` (WOTS_C_Reduction.ec:378): for each
   committed query it grinds a +C counter via the collection oracle (pp hidden in
   `choose`), commits the +C digest `ThC(pp,wad,m,c)` as the WOTS-TW message, then
   in `forge` reconstructs each WOTS+C signature (WOTS-TW sig, grinded counter),
   drives A, and relays A's forgery as a WOTS-TW forgery ON THE +C DIGEST.
   REAL module, zero admit.
   ========================================================================== *)
module (R_multi_WOTSTW (A : Adv_MnaCMA_WOTSC) : Adv_MnaCMA_WOTSTW)
       (OC : STCRC_WC.Col.Oracle_THFC) = {
  module AA = A(OC)
  var qs : qC list
  var sds : cntr list

  (* Commit, per query, (wad, ThC-digest); remember the grinded counter. *)
  proc choose() : qTW list = {
    var k : int;
    var wad : wadrs;
    var m : dgstblock;
    var cs : cntr list;
    var seed : cntr;
    var sd : cntr;
    var y, d : msgWOTS;
    var found : bool;
    var qres : qTW list;

    qs <@ AA.choose();
    qres <- []; sds <- []; k <- 0;
    while (k < size qs) {
      wad <- (nth witness qs k).`1;
      m   <- (nth witness qs k).`2;
      (* grind a Prop-satisfying counter via the collection oracle *)
      cs <- STCRC_WC.G.CntrFT.enum;
      found <- false; sd <- witness;
      while (!found /\ cs <> []) {
        seed <- head witness cs;
        y <@ OC.query(WAddress.val wad, (m, seed));
        if (predC y) { sd <- seed; found <- true; }
        cs <- behead cs;
      }
      d <@ OC.query(WAddress.val wad, (m, sd));
      (* The WOTS-TW committed message for instance k IS the +C digest d
         (= ThC pp wad m sd); d : msgWOTS is the WIDE digest, m : dgstblock the node [route (D)];
         well-typed as the WOTS-TW message.  This is the Algorithm-10 bridge:
         WOTS+C-signing m  ==  WOTS-TW-signing ThC(pp,wad,m,grind) + the counter. *)
      qres <- rcons qres (wad, d);
      sds <- rcons sds sd;
      k <- k + 1;
    }
    return qres;
  }

  proc forge(ps : pseed, ks : (pkWOTS * sigWOTS) list)
       : int * msgWOTS * sigWOTS = {
    var k : int;
    var wcks : (pkWOTS * (sigWOTS * cntr)) list;
    var i : int;
    var m' : dgstblock;   (* A's +C forgery is a NODE; ThC lifts it below *)
    var sigc' : sigWOTS * cntr;

    wcks <- []; k <- 0;
    while (k < size ks) {
      wcks <- rcons wcks ((nth witness ks k).`1,
                          ((nth witness ks k).`2, nth witness sds k));
      k <- k + 1;
    }

    (i, m', sigc') <@ AA.forge(ps, wcks);

    return (i, ThC ps (WAddress.val (nth witness qs i).`1) m' sigc'.`2, sigc'.`1);
  }
}.

(* ==========================================================================
   GAME.1 (multi) — M_EUF_NACMA_WOTSC_L with the extra loss condition that NO
   Th+C collision is extractable at the forged instance i:
     ! ( ThC ps ad_i m_i j_i = ThC ps ad_i m' c' ),
   where (ad_i, m_i, j_i) is instance i's honest (address, message, counter) and
   (m', c') is A's forgery.  The GAME.0 -> GAME.1 gap is bounded by S-TCR(+C).
   (Multi-instance analogue of GAME1_WOTSC, WOTS_C_Reduction.ec:103.)
   ========================================================================== *)
module GAME1_MULTI(A : Adv_MnaCMA_WOTSC, OC : STCRC_WC.Col.Oracle_THFC) = {
  module AA = A(OC)

  proc main() : bool = {
    var ps : pseed;
    var qs : qC list;
    var ks : (pkWOTS * (sigWOTS * cntr)) list;
    var adlO, adlOC : adrs list;
    var wad : wadrs;
    var m, m' : dgstblock;
    var pk : pkWOTSTW;
    var sk : skWOTS * pseed * adrs;
    var sigc, sigc' : sigWOTS * cntr;
    var i, k : int;
    var is_valid, is_fresh, dist_wgpidxs : bool;
    var nrqs : int;

    ps <$ dpseed;
    OC.init(ps);
    qs <@ AA.choose();

    ks <- []; adlO <- []; k <- 0;
    while (k < size qs) {
      wad <- (nth witness qs k).`1;
      m   <- (nth witness qs k).`2;
      (pk, sk) <@ WOTS_C_ES.keygen(ps, WAddress.val wad);
      sigc <@ WOTS_C_ES.sign(sk, m);
      ks   <- rcons ks (pk.`1, sigc);
      adlO <- rcons adlO (WAddress.val wad);
      k <- k + 1;
    }

    (i, m', sigc') <@ AA.forge(ps, ks);

    wad <- (nth witness qs i).`1;
    m   <- (nth witness qs i).`2;
    is_valid <@ WOTS_C_ES.verify(((nth witness ks i).`1, ps, WAddress.val wad), m', sigc');
    is_fresh <- m' <> m;

    nrqs <- size qs;
    dist_wgpidxs <- uniq_wgpidxs adlO;
    adlOC <@ OC.get_tweaks();

    return 0 <= nrqs <= c /\ 0 <= i < nrqs /\
           is_valid /\ is_fresh /\ dist_wgpidxs /\ disj_wgpidxs adlO adlOC /\
           ! (ThC ps (WAddress.val wad) m (nth witness ks i).`2.`2
              = ThC ps (WAddress.val wad) m' sigc'.`2);
  }
}.

(* GAME.0 (multi) instrumented: identical returned bit to M_EUF_NACMA_WOTSC_L,
   but records the collision event at instance i in a global.  The extra
   assignment does not touch the returned bit. *)
module G0_MULTI(A : Adv_MnaCMA_WOTSC, OC : STCRC_WC.Col.Oracle_THFC) = {
  module AA = A(OC)
  var coll : bool

  proc main() : bool = {
    var ps : pseed;
    var qs : qC list;
    var ks : (pkWOTS * (sigWOTS * cntr)) list;
    var adlO, adlOC : adrs list;
    var wad : wadrs;
    var m, m' : dgstblock;
    var pk : pkWOTSTW;
    var sk : skWOTS * pseed * adrs;
    var sigc, sigc' : sigWOTS * cntr;
    var i, k : int;
    var is_valid, is_fresh, dist_wgpidxs : bool;
    var nrqs : int;

    ps <$ dpseed;
    OC.init(ps);
    qs <@ AA.choose();

    ks <- []; adlO <- []; k <- 0;
    while (k < size qs) {
      wad <- (nth witness qs k).`1;
      m   <- (nth witness qs k).`2;
      (pk, sk) <@ WOTS_C_ES.keygen(ps, WAddress.val wad);
      sigc <@ WOTS_C_ES.sign(sk, m);
      ks   <- rcons ks (pk.`1, sigc);
      adlO <- rcons adlO (WAddress.val wad);
      k <- k + 1;
    }

    (i, m', sigc') <@ AA.forge(ps, ks);

    wad <- (nth witness qs i).`1;
    m   <- (nth witness qs i).`2;
    is_valid <@ WOTS_C_ES.verify(((nth witness ks i).`1, ps, WAddress.val wad), m', sigc');
    is_fresh <- m' <> m;

    nrqs <- size qs;
    dist_wgpidxs <- uniq_wgpidxs adlO;
    adlOC <@ OC.get_tweaks();

    coll <- (ThC ps (WAddress.val wad) m (nth witness ks i).`2.`2
             = ThC ps (WAddress.val wad) m' sigc'.`2);
    return 0 <= nrqs <= c /\ 0 <= i < nrqs /\
           is_valid /\ is_fresh /\ dist_wgpidxs /\ disj_wgpidxs adlO adlOC;
  }
}.

(* ==========================================================================
   Predicate bridges consumed by D1_reduce (the game success conditions differ
   in form between the WOTS+C game and the multi-target S-TCR(+C) game: the
   former uses the WOTS group-prefix predicates `uniq_wgpidxs` / `disj_wgpidxs`,
   the latter the plain-list `uniq` / `Col.disj_lists`).  These lemmas discharge
   the "res{1} => res{2}" transfer of those conjuncts.  Zero admit.
   ========================================================================== *)

(* Distinct WOTS group-prefixes imply distinct addresses (the S-TCR `dist`). *)
lemma uniq_wgpidxs_uniq (adl : adrs list) :
  uniq_wgpidxs adl => uniq adl.
proof. by rewrite /uniq_wgpidxs; apply uniq_map. qed.

(* Group-prefix disjointness implies plain-list (tweak) disjointness — the
   S-TCR `disj_lists twsO twsOC` follows from the WOTS+C game's disj_wgpidxs. *)
lemma disj_wgpidxs_disj_lists (adl adl' : adrs list) :
  disj_wgpidxs adl adl' => STCRC_WC.Col.disj_lists adl adl'.
proof.
  rewrite /disj_wgpidxs => /hasPn h.
  apply/hasPn => x xin.
  have hy := h (get_wgpidxs x) _; first by apply map_f.
  by move: hy; smt(map_f).
qed.

(* The recorded S-TCR target list's tweak-projection is exactly the WOTS+C
   game's committed-address list — the target/instance address alignment that
   turns `dist`/`disj_lists` on the S-TCR side into `uniq_wgpidxs`/`disj_wgpidxs`
   on the WOTS+C side. *)
lemma map_fst_targets (ps0 : pseed) (l : qC list) :
  map (fun (tmc : adrs * dgstblock * cntr) => tmc.`1)
      (map (fun (q : qC) =>
              (WAddress.val q.`1, q.`2, grindC ps0 (WAddress.val q.`1) q.`2)) l)
  = map (fun (q : qC) => WAddress.val q.`1) l.
proof. by rewrite -map_comp /(\o). qed.

(* ==========================================================================
   Thm D.1, first game-hop.  GAME.0 (multi) <= GAME.1 (multi) + S-TCR(+C) via
   the Algorithm-9 reduction R_multi_STCRC.  Structure mirrors C.2's
   WOTSC_C2_hop1 (WOTS_C_Reduction.ec:304): instrument GAME.0 (`G0_MULTI`),
   split on the collision event; the no-collision part IS GAME.1, the collision
   part is caught by the multi-target S-TCR(+C) game through R_multi_STCRC.
   ========================================================================== *)

(* The collision part of GAME.0 (multi) is bounded by the multi-target S-TCR(+C)
   game.  This is the core multi-instance pRHL of Algorithm 9 — the d-query lift
   of C.2's WOTSC_C2_reduce (WOTS_C_Reduction.ec:229). *)
lemma D1_reduce
  (A <: Adv_MnaCMA_WOTSC{-R_multi_STCRC, -STCRC_WC.O_STCRC_Default,
                         -STCRC_WC.Col.O_THFC_Default, -G0_MULTI}) &m :
    (* (a) target-count: the reduction places one S-TCR(+C) target per committed
       query; the game caps nrqs <= c, so the S-TCR cap nrts <= p_stcr (= p_tgts)
       needs `c <= p_tgts`.  Multi-instance analogue of C.2's `1 <= p_tgts`. *)
    c <= p_tgts =>
    Pr[G0_MULTI(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res /\ G0_MULTI.coll]
  <= Pr[STCRC_WC.S_TCR_C(R_multi_STCRC(A),
                         STCRC_WC.O_STCRC_Default,
                         STCRC_WC.Col.O_THFC_Default).main() @ &m : res].
proof.
  (* -----------------------------------------------------------------------
     PROVED (zero admit).  HEADING CORRECTED 2026-08-18: this block was headed
     "LABELLED ADMIT (D.1 hop1 core, Algorithm 9 multi-instance byequiv)" and
     closed with a "Remaining work" note, both written while the proof below was
     still open.  The byequiv is complete and closed by the `qed` that ends this
     lemma, and scratch/sweep.py reports admit=0 axiom=0 sorry=0 for the file.
     The obligation description is KEPT verbatim below, because it still says
     exactly what the proof discharges -- only the two staleness claims are gone.

     Obligation: byequiv G0_MULTI ~ S_TCR_C(R_multi_STCRC(A)) coupling
       (res{1} /\ coll{1}) => res{2}, i.e. the d-query lift of the single-query
     coupling proved in WOTS_C_Reduction.ec:245-298 (WOTSC_C2_reduce).  Concretely
     the loop-coupling: R_multi_STCRC.pick's target-registration loop couples with
     G0_MULTI's per-instance keygen+sign loop so that, for every committed index k,
       target k's recorded (tw_k, m_k, j_k) = (WAddress.val wad_k, m_k, grindC ..),
     and the honest instance-k counter (nth ks k).`2.`2 = grindC .. = j_k (grind is
     deterministic; sign_ctr2 lifted per-index).  Then the collision event at the
     forged instance i (G0_MULTI.coll with res) maps exactly to S_TCR_C success at
     target i: ThC pp tw_i m_i j_i = ThC pp tw_i m' ctr with m' <> m_i, plus the
     target-count bound (c <= p_tgts => nrts <= p_stcr) and the collection
     disjointness (per-instance address separation, the multi lift of C.2's `sep`).
     ----------------------------------------------------------------------- *)
  move=> le_c_ptgts.
  byequiv (_ : ={glob A} ==> (res{1} /\ G0_MULTI.coll{1}) => res{2}) => //.
  proc.
  inline{2} R_multi_STCRC(A, STCRC_WC.O_STCRC_Default, STCRC_WC.Col.O_THFC_Default).pick.
  inline{2} R_multi_STCRC(A, STCRC_WC.O_STCRC_Default, STCRC_WC.Col.O_THFC_Default).find.
  inline{2} STCRC_WC.O_STCRC_Default.init STCRC_WC.O_STCRC_Default.query
            STCRC_WC.O_STCRC_Default.get STCRC_WC.O_STCRC_Default.nr_targets
            STCRC_WC.O_STCRC_Default.dist_tweaks STCRC_WC.O_STCRC_Default.get_tweaks
            STCRC_WC.Col.O_THFC_Default.get_tweaks.
  inline{1} STCRC_WC.Col.O_THFC_Default.init STCRC_WC.Col.O_THFC_Default.get_tweaks.
  inline{2} STCRC_WC.Col.O_THFC_Default.init.
  have ch_eq :
    equiv[A(STCRC_WC.Col.O_THFC_Default).choose ~ A(STCRC_WC.Col.O_THFC_Default).choose :
            ={glob A, glob STCRC_WC.Col.O_THFC_Default}
            ==> ={glob A, glob STCRC_WC.Col.O_THFC_Default, res}].
  + by sim.
  seq 1 1 : (={glob A} /\ ps{1} = pp{2}).
  + rnd; skip => />.
  sp.
  seq 1 1 : (={glob A, glob STCRC_WC.Col.O_THFC_Default} /\ ps{1} = pp{2}
             /\ qs{1} = R_multi_STCRC.qs{2}
             /\ STCRC_WC.O_STCRC_Default.pp{2} = pp{2}
             /\ STCRC_WC.O_STCRC_Default.ts{2} = []).
  + call ch_eq; skip => />.
  seq 3 2 : (={glob A, glob STCRC_WC.Col.O_THFC_Default} /\ ps{1} = pp{2}
             /\ qs{1} = R_multi_STCRC.qs{2}
             /\ ks{1} = [] /\ adlO{1} = [] /\ k{1} = 0
             /\ STCRC_WC.O_STCRC_Default.pp{2} = pp{2}
             /\ STCRC_WC.O_STCRC_Default.ts{2}
                = map (fun (q : qC) => (WAddress.val q.`1, q.`2,
                        grindC pp{2} (WAddress.val q.`1) q.`2)) R_multi_STCRC.qs{2}).
  + sp.
    while{2} (={glob A, glob STCRC_WC.Col.O_THFC_Default} /\ ps{1} = pp{2}
              /\ qs{1} = R_multi_STCRC.qs{2} /\ ks{1} = [] /\ adlO{1} = [] /\ k{1} = 0
              /\ STCRC_WC.O_STCRC_Default.pp{2} = pp{2}
              /\ 0 <= k{2} <= size R_multi_STCRC.qs{2}
              /\ STCRC_WC.O_STCRC_Default.ts{2}
                 = map (fun (q : qC) => (WAddress.val q.`1, q.`2,
                         grindC pp{2} (WAddress.val q.`1) q.`2)) (take k{2} R_multi_STCRC.qs{2}))
             (size R_multi_STCRC.qs{2} - k{2}).
    + move=> &1 z; wp; skip => /> &2 *; smt(take_nth map_rcons grindC_E size_ge0 nth_take size_take).
    skip => /> *; smt(take0 take_size size_ge0 size_take).
  sp.
  seq 1 1 : (={glob A, glob STCRC_WC.Col.O_THFC_Default} /\ ps{1} = pp{2}
             /\ pp0{2} = pp{2}
             /\ qs{1} = R_multi_STCRC.qs{2} /\ ={ks} /\ size ks{1} = size qs{1}
             /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) qs{1}
             /\ STCRC_WC.O_STCRC_Default.pp{2} = pp{2}
             /\ STCRC_WC.O_STCRC_Default.ts{2}
                = map (fun (q : qC) => (WAddress.val q.`1, q.`2,
                        grindC pp{2} (WAddress.val q.`1) q.`2)) R_multi_STCRC.qs{2}
             /\ (forall idx, 0 <= idx < size qs{1} =>
                   (nth witness ks{1} idx).`2.`2
                   = grindC pp{2} (WAddress.val (nth witness qs{1} idx).`1)
                                  (nth witness qs{1} idx).`2)).
  + while (={glob A, glob STCRC_WC.Col.O_THFC_Default} /\ ps{1} = pp{2}
           /\ pp0{2} = pp{2}
           /\ qs{1} = R_multi_STCRC.qs{2} /\ ={ks} /\ size ks{1} = k{1} /\ k{1} = k0{2}
           /\ 0 <= k{1} <= size qs{1}
           /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) (take k{1} qs{1})
           /\ STCRC_WC.O_STCRC_Default.pp{2} = pp{2}
           /\ STCRC_WC.O_STCRC_Default.ts{2}
              = map (fun (q : qC) => (WAddress.val q.`1, q.`2,
                      grindC pp{2} (WAddress.val q.`1) q.`2)) R_multi_STCRC.qs{2}
           /\ (forall idx, 0 <= idx < k{1} =>
                 (nth witness ks{1} idx).`2.`2
                 = grindC pp{2} (WAddress.val (nth witness qs{1} idx).`1)
                                (nth witness qs{1} idx).`2)).
    + sp.
      exists* ps{1}, (WAddress.val wad{1}), m{1}; elim* => psv adv mv.
      wp.
      call (sign_eqs2 psv adv mv).
      call (keygen_eqs psv adv).
      skip => />; smt(nth_rcons size_rcons take_nth map_rcons).
    skip => />; smt(take0 take_size size_ge0 size_take).
  wp.
  call{1} verify_ll.
  wp.
  call (_ : true).
  skip => /> &2 hsize hf result_R result h0s hsc h0i his hval hfr hu hd hcoll.
  have hci := hf result_R.`1 _; first by rewrite h0i his.
  rewrite !size_map !(nth_map witness witness) 1:/# /= map_fst_targets.
  smt(uniq_wgpidxs_uniq disj_wgpidxs_disj_lists).
qed.

lemma D1_hop1
  (A <: Adv_MnaCMA_WOTSC{-R_multi_STCRC, -STCRC_WC.O_STCRC_Default,
                         -STCRC_WC.Col.O_THFC_Default, -G0_MULTI}) &m :
    c <= p_tgts =>
    Pr[M_EUF_NACMA_WOTSC_L(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
  <=   Pr[GAME1_MULTI(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
     + Pr[STCRC_WC.S_TCR_C(R_multi_STCRC(A),
                           STCRC_WC.O_STCRC_Default,
                           STCRC_WC.Col.O_THFC_Default).main() @ &m : res].
proof.
  move=> le_c_ptgts.
  (* instrument: Pr[GAME.0] = Pr[G0_MULTI] (returned bit identical; G0_MULTI's
     only extra statement is the `coll` record, which does not touch res). *)
  have e0 : Pr[M_EUF_NACMA_WOTSC_L(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
          = Pr[G0_MULTI(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res].
  + byequiv (_ : ={glob A} ==> res{1} = res{2}) => //; proc.
    seq 15 15 : (={ps, qs, ks, adlO, i, m, m', sigc', is_valid, is_fresh,
                   dist_wgpidxs, nrqs, wad, adlOC}
                 /\ ={glob STCRC_WC.Col.O_THFC_Default}).
    + sim.
    wp; skip => />.
  rewrite e0 Pr[mu_split (G0_MULTI.coll)].
  (* the no-collision part IS GAME.1: G0_MULTI.coll{1} is exactly GAME.1's extra
     non-collision conjunct, so (res{1} /\ !coll{1}) <=> res{2}. *)
  have e1 : Pr[G0_MULTI(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res /\ !G0_MULTI.coll]
          = Pr[GAME1_MULTI(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res].
  + byequiv (_ : ={glob A} ==> res{1} /\ ! G0_MULTI.coll{1} <=> res{2}) => //; proc.
    seq 15 15 : (={ps, qs, ks, adlO, i, m, m', sigc', is_valid, is_fresh,
                   dist_wgpidxs, nrqs, wad, adlOC}
                 /\ ={glob STCRC_WC.Col.O_THFC_Default}).
    + sim.
    wp; skip => />; smt().
  rewrite e1.
  (* the collision part is the reduction *)
  have e2 := D1_reduce A &m le_c_ptgts.
  smt().
qed.

(* WOTS-TW verify is lossless (used one-sided in D1_hop2's out-of-range
   branch, where the forged index i is out of range so res{1} is false). *)
lemma verifytw_ll : islossless WOTS_TW_ES_NPRF.verify.
proof. islossless; while true (len - size pkWOTS); auto; smt(size_rcons). qed.

(* ==========================================================================
   Thm D.1, second game-hop.  GAME.1 (multi) <= d-EU-naCMA(WOTS-TW) via the
   Algorithm-10 reduction R_multi_WOTSTW.  Multi-instance lift of C.2's
   WOTSC_C2_hop2 (WOTS_C_Reduction.ec:548), under the same encode-bridge
   hypothesis (encode_msgWOTS_C = encode_msgWOTS o ThC).
   ========================================================================== *)
lemma D1_hop2
  (A <: Adv_MnaCMA_WOTSC{-R_multi_WOTSTW, -STCRC_WC.Col.O_THFC_Default}) &m :
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    Pr[GAME1_MULTI(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
  <= Pr[M_EUF_NACMA_WOTSTW_L(R_multi_WOTSTW(A), STCRC_WC.Col.O_THFC_Default).main() @ &m : res].
proof.
  (* PROVED (zero admit) 2026-07-08 — d-query lift of C.2's WOTSC_C2_hop2.
     Per committed index k: R_multi_WOTSTW.choose grinds sd_k via the collection
     oracle and commits d_k = ThC pp wad_k m_k sd_k as the WOTS-TW message (the
     nested grind-scan-inside-commit while{2}, Block C); keygen is shared and,
     under `encb`, WOTS+C-sign = WOTS-TW-sign on d_k with counter sd_k (Block D);
     A's forgery on instance i transfers via verifyC_TW and GAME.1's non-collision
     IS the WOTS-TW freshness `m'{2} <> m{2}`.  Out-of-range i => res{1} false. *)
move=> encb.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc.
inline{2} R_multi_WOTSTW(A, STCRC_WC.Col.O_THFC_Default).choose.
inline{2} R_multi_WOTSTW(A, STCRC_WC.Col.O_THFC_Default).forge.
inline{1} STCRC_WC.Col.O_THFC_Default.init.
inline{2} STCRC_WC.Col.O_THFC_Default.init.
inline{2} STCRC_WC.Col.O_THFC_Default.query.
inline{1} STCRC_WC.Col.O_THFC_Default.get_tweaks.
inline{2} STCRC_WC.Col.O_THFC_Default.get_tweaks.
(* ch_eq: A.choose perfectly simulated *)
have ch_eq :
  equiv[A(STCRC_WC.Col.O_THFC_Default).choose ~ A(STCRC_WC.Col.O_THFC_Default).choose :
          ={glob A, glob STCRC_WC.Col.O_THFC_Default}
          ==> ={glob A, glob STCRC_WC.Col.O_THFC_Default, res}].
+ by sim.
(* Block A: sample + init *)
seq 4 4 : (={glob A, glob STCRC_WC.Col.O_THFC_Default} /\ ps{1} = ps{2}
           /\ STCRC_WC.Col.O_THFC_Default.pp{1} = ps{1}).
+ auto.
(* Block B: A.choose *)
seq 1 1 : (={glob A, glob STCRC_WC.Col.O_THFC_Default} /\ ps{1} = ps{2}
           /\ STCRC_WC.Col.O_THFC_Default.pp{1} = ps{1}
           /\ qs{1} = R_multi_WOTSTW.qs{2}).
+ call ch_eq; skip => />.
(* Block C: side-2-only grind loop, establishes the map facts *)
seq 0 5 : (={glob A} /\ ps{1} = ps{2}
           /\ STCRC_WC.Col.O_THFC_Default.pp{1} = ps{1}
           /\ qs{1} = R_multi_WOTSTW.qs{2}
           /\ qs{2} = map (fun (q : qC) =>
                 (q.`1, ThC ps{1} (WAddress.val q.`1) q.`2
                          (grindC ps{1} (WAddress.val q.`1) q.`2))) qs{1}
           /\ R_multi_WOTSTW.sds{2} = map (fun (q : qC) =>
                 grindC ps{1} (WAddress.val q.`1) q.`2) qs{1}).
+ wp.
  while{2} (   STCRC_WC.Col.O_THFC_Default.pp{2} = ps{1}
            /\ 0 <= k0{2} <= size R_multi_WOTSTW.qs{2}
            /\ qres{2} = map (fun (q : qC) =>
                  (q.`1, ThC ps{1} (WAddress.val q.`1) q.`2
                           (grindC ps{1} (WAddress.val q.`1) q.`2)))
                  (take k0{2} R_multi_WOTSTW.qs{2})
            /\ R_multi_WOTSTW.sds{2} = map (fun (q : qC) =>
                  grindC ps{1} (WAddress.val q.`1) q.`2)
                  (take k0{2} R_multi_WOTSTW.qs{2}))
           (size R_multi_WOTSTW.qs{2} - k0{2}).
  + move=> &1 z.
    wp.
    while (   STCRC_WC.Col.O_THFC_Default.pp = ps{1}
           /\ (found => sd = grindC ps{1} (WAddress.val wad0) m0)
           /\ (!found => sd = witness)
           /\ (!found =>
                 head witness
                   (filter (fun c => predC (ThC ps{1} (WAddress.val wad0) m0 c)) cs)
                 = grindC ps{1} (WAddress.val wad0) m0))
          (size cs).
    + auto => /> *; smt(STCRC_WC.G.head_filter_ne size_behead size_ge0 size_eq0).
    auto => /> *; smt(grindC_filter take_nth map_rcons grindC_E size_ge0 size_eq0).
  auto => /> *; smt(take0 take_size size_ge0).
(* Block D-pre: ks/adlO/k init *)
seq 3 3 : (={glob A} /\ ps{1} = ps{2} /\ STCRC_WC.Col.O_THFC_Default.pp{1} = ps{1}
           /\ qs{1} = R_multi_WOTSTW.qs{2}
           /\ qs{2} = map (fun (q : qC) =>
                 (q.`1, ThC ps{1} (WAddress.val q.`1) q.`2
                          (grindC ps{1} (WAddress.val q.`1) q.`2))) qs{1}
           /\ R_multi_WOTSTW.sds{2} = map (fun (q : qC) =>
                 grindC ps{1} (WAddress.val q.`1) q.`2) qs{1}
           /\ ks{1} = [] /\ ks{2} = [] /\ ={adlO} /\ adlO{1} = [] /\ ={k} /\ k{1} = 0).
+ auto.
(* Block D: keygen + sign loop, two-sided *)
seq 1 1 : (={glob A} /\ ps{1} = ps{2} /\ STCRC_WC.Col.O_THFC_Default.pp{1} = ps{1}
           /\ qs{1} = R_multi_WOTSTW.qs{2}
           /\ qs{2} = map (fun (q : qC) =>
                 (q.`1, ThC ps{1} (WAddress.val q.`1) q.`2
                          (grindC ps{1} (WAddress.val q.`1) q.`2))) qs{1}
           /\ R_multi_WOTSTW.sds{2} = map (fun (q : qC) =>
                 grindC ps{1} (WAddress.val q.`1) q.`2) qs{1}
           /\ ={adlO} /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) qs{1}
           /\ size ks{1} = size qs{1} /\ size ks{2} = size qs{1}
           /\ (forall idx, 0 <= idx < size qs{1} =>
                 (nth witness ks{1} idx).`1 = (nth witness ks{2} idx).`1
              /\ (nth witness ks{1} idx).`2.`1 = (nth witness ks{2} idx).`2
              /\ (nth witness ks{1} idx).`2.`2
                 = grindC ps{1} (WAddress.val (nth witness qs{1} idx).`1)
                                (nth witness qs{1} idx).`2)).
+ while (={glob A} /\ ps{1} = ps{2} /\ STCRC_WC.Col.O_THFC_Default.pp{1} = ps{1}
         /\ qs{1} = R_multi_WOTSTW.qs{2}
         /\ qs{2} = map (fun (q : qC) =>
               (q.`1, ThC ps{1} (WAddress.val q.`1) q.`2
                        (grindC ps{1} (WAddress.val q.`1) q.`2))) qs{1}
         /\ R_multi_WOTSTW.sds{2} = map (fun (q : qC) =>
               grindC ps{1} (WAddress.val q.`1) q.`2) qs{1}
         /\ ={k} /\ 0 <= k{1} <= size qs{1}
         /\ size ks{1} = k{1} /\ size ks{2} = k{1}
         /\ ={adlO} /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) (take k{1} qs{1})
         /\ (forall idx, 0 <= idx < k{1} =>
               (nth witness ks{1} idx).`1 = (nth witness ks{2} idx).`1
            /\ (nth witness ks{1} idx).`2.`1 = (nth witness ks{2} idx).`2
            /\ (nth witness ks{1} idx).`2.`2
               = grindC ps{1} (WAddress.val (nth witness qs{1} idx).`1)
                              (nth witness qs{1} idx).`2)).
  + sp.
    exists* ps{1}, (WAddress.val wad{1}), m{1}; elim* => psv adv mv.
    wp.
    call (signC_TW psv adv mv encb).
    call (keygenC_TW_s psv adv).
    skip => /> *; smt(nth_rcons size_rcons take_nth map_rcons nth_map size_map).
  skip => />.
  move=> &2; rewrite take0 /= !size_map.
  split.
  + smt(size_ge0).
  move=> ksL ksR hstopL hstopR hnonneg hbound hsizes hinv.
  have hdone : size ksL = size R_multi_WOTSTW.qs{2} by smt().
  rewrite hdone take_size /= hsizes hdone /=.
  move=> idx h0 hlt; apply hinv; rewrite hdone.
  by split.
(* Block E-pre: side-2-only wcks reconstruction, wcks{2} = ks{1} *)
seq 0 5 : (={glob A} /\ ps{1} = ps{2} /\ STCRC_WC.Col.O_THFC_Default.pp{1} = ps{1}
           /\ qs{1} = R_multi_WOTSTW.qs{2}
           /\ qs{2} = map (fun (q : qC) =>
                 (q.`1, ThC ps{1} (WAddress.val q.`1) q.`2
                          (grindC ps{1} (WAddress.val q.`1) q.`2))) qs{1}
           /\ ={adlO} /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) qs{1}
           /\ size ks{1} = size qs{1} /\ size ks{2} = size qs{1}
           /\ (forall idx, 0 <= idx < size qs{1} =>
                 (nth witness ks{1} idx).`1 = (nth witness ks{2} idx).`1
              /\ (nth witness ks{1} idx).`2.`1 = (nth witness ks{2} idx).`2
              /\ (nth witness ks{1} idx).`2.`2
                 = grindC ps{1} (WAddress.val (nth witness qs{1} idx).`1)
                                (nth witness qs{1} idx).`2)
           /\ ps0{2} = ps{2} /\ wcks{2} = ks{1}).
+ sp.
  while{2} (   ps0{2} = ps{2} /\ ks0{2} = ks{2}
            /\ 0 <= k1{2} <= size ks{2}
            /\ R_multi_WOTSTW.sds{2} = map (fun (q : qC) =>
                  grindC ps{1} (WAddress.val q.`1) q.`2) qs{1}
            /\ qs{1} = R_multi_WOTSTW.qs{2}
            /\ size ks{1} = size qs{1} /\ size ks{2} = size qs{1}
            /\ (forall idx, 0 <= idx < size qs{1} =>
                  (nth witness ks{1} idx).`1 = (nth witness ks{2} idx).`1
               /\ (nth witness ks{1} idx).`2.`1 = (nth witness ks{2} idx).`2
               /\ (nth witness ks{1} idx).`2.`2
                  = grindC ps{1} (WAddress.val (nth witness qs{1} idx).`1)
                                 (nth witness qs{1} idx).`2)
            /\ wcks{2} = take k1{2} ks{1})
           (size ks{2} - k1{2}).
  + move=> &1 z. auto => /> *; smt(take_nth nth_map size_map size_ge0).
  auto => /> *; smt(take0 take_size size_ge0).
(* Block E-forge: couple A.forge (oracle-free) *)
seq 1 1 : (={glob A} /\ ps{1} = ps{2} /\ STCRC_WC.Col.O_THFC_Default.pp{1} = ps{1}
           /\ qs{1} = R_multi_WOTSTW.qs{2}
           /\ qs{2} = map (fun (q : qC) =>
                 (q.`1, ThC ps{1} (WAddress.val q.`1) q.`2
                          (grindC ps{1} (WAddress.val q.`1) q.`2))) qs{1}
           /\ ={adlO} /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) qs{1}
           /\ size ks{1} = size qs{1} /\ size ks{2} = size qs{1}
           /\ (forall idx, 0 <= idx < size qs{1} =>
                 (nth witness ks{1} idx).`1 = (nth witness ks{2} idx).`1
              /\ (nth witness ks{1} idx).`2.`1 = (nth witness ks{2} idx).`2
              /\ (nth witness ks{1} idx).`2.`2
                 = grindC ps{1} (WAddress.val (nth witness qs{1} idx).`1)
                                (nth witness qs{1} idx).`2)
           /\ ps0{2} = ps{2}
           /\ i{1} = i0{2} /\ m'{1} = m'0{2} /\ sigc'{1} = sigc'{2}).
+ call (: true); skip => /> *.
(* Block E-ret: side-2-only return-assign *)
seq 0 1 : (={glob A} /\ ps{1} = ps{2} /\ STCRC_WC.Col.O_THFC_Default.pp{1} = ps{1}
           /\ qs{1} = R_multi_WOTSTW.qs{2}
           /\ qs{2} = map (fun (q : qC) =>
                 (q.`1, ThC ps{1} (WAddress.val q.`1) q.`2
                          (grindC ps{1} (WAddress.val q.`1) q.`2))) qs{1}
           /\ ={adlO} /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) qs{1}
           /\ size ks{1} = size qs{1} /\ size ks{2} = size qs{1}
           /\ (forall idx, 0 <= idx < size qs{1} =>
                 (nth witness ks{1} idx).`1 = (nth witness ks{2} idx).`1
              /\ (nth witness ks{1} idx).`2.`1 = (nth witness ks{2} idx).`2
              /\ (nth witness ks{1} idx).`2.`2
                 = grindC ps{1} (WAddress.val (nth witness qs{1} idx).`1)
                                (nth witness qs{1} idx).`2)
           /\ i{1} = i{2}
           /\ m'{2} = ThC ps{1} (WAddress.val (nth witness qs{1} i{1}).`1) m'{1} sigc'{1}.`2
           /\ sig'{2} = sigc'{1}.`1).
+ wp; skip => /> *.
(* Block F: wad, m assignments (aligned) *)
seq 2 2 : (={glob A} /\ ps{1} = ps{2}
           /\ qs{1} = R_multi_WOTSTW.qs{2}
           /\ qs{2} = map (fun (q : qC) =>
                 (q.`1, ThC ps{1} (WAddress.val q.`1) q.`2
                          (grindC ps{1} (WAddress.val q.`1) q.`2))) qs{1}
           /\ ={adlO} /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) qs{1}
           /\ size ks{1} = size qs{1} /\ size ks{2} = size qs{1}
           /\ (forall idx, 0 <= idx < size qs{1} =>
                 (nth witness ks{1} idx).`1 = (nth witness ks{2} idx).`1
              /\ (nth witness ks{1} idx).`2.`1 = (nth witness ks{2} idx).`2
              /\ (nth witness ks{1} idx).`2.`2
                 = grindC ps{1} (WAddress.val (nth witness qs{1} idx).`1)
                                (nth witness qs{1} idx).`2)
           /\ size qs{2} = size qs{1}
           /\ i{1} = i{2}
           /\ m'{2} = ThC ps{1} (WAddress.val (nth witness qs{1} i{1}).`1) m'{1} sigc'{1}.`2
           /\ sig'{2} = sigc'{1}.`1
           /\ wad{1} = (nth witness qs{1} i{1}).`1 /\ m{1} = (nth witness qs{1} i{1}).`2
           /\ wad{2} = (nth witness qs{2} i{2}).`1 /\ m{2} = (nth witness qs{2} i{2}).`2).
+ wp; skip => /> *; smt(size_map).
(* verify + tail, case-split on whether the forged index i is in range.
   In range: verifyC_TW couples validity.  Out of range: res{1} is false
   (0 <= i < nrqs fails), so res{1} => res{2} holds vacuously and the two
   verify calls are run one-sided-lossless (no ={pk} available since the
   out-of-range nth's are differently-typed witnesses). *)
case (0 <= i{1} < size qs{1}).
+ (* ---- in range ---- *)
  exists* ps{1}, (WAddress.val wad{1}), m'{1}, (sigc'{1}.`2); elim* => psv adv mAv cAv.
  seq 1 1 : (ps{1} = ps{2}
             /\ qs{1} = R_multi_WOTSTW.qs{2}
             /\ qs{2} = map (fun (q : qC) =>
                   (q.`1, ThC ps{1} (WAddress.val q.`1) q.`2
                            (grindC ps{1} (WAddress.val q.`1) q.`2))) qs{1}
             /\ ={adlO} /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) qs{1}
             /\ size ks{1} = size qs{1} /\ size ks{2} = size qs{1}
             /\ (forall idx, 0 <= idx < size qs{1} =>
                   (nth witness ks{1} idx).`2.`2
                   = grindC ps{1} (WAddress.val (nth witness qs{1} idx).`1)
                                  (nth witness qs{1} idx).`2)
             /\ size qs{2} = size qs{1}
             /\ 0 <= i{1} < size qs{1} /\ i{1} = i{2}
             /\ m'{2} = ThC ps{1} (WAddress.val (nth witness qs{1} i{1}).`1) m'{1} sigc'{1}.`2
             /\ wad{1} = (nth witness qs{1} i{1}).`1 /\ m{1} = (nth witness qs{1} i{1}).`2
             /\ wad{2} = (nth witness qs{2} i{2}).`1 /\ m{2} = (nth witness qs{2} i{2}).`2
             /\ (is_valid{1} => is_valid{2})).
  + call (verifyC_TW psv adv mAv cAv encb); skip => /> *; smt(nth_map size_map).
  wp; skip => /> *; smt(nth_map size_map).
(* ---- out of range: res{1} is false ---- *)
wp.
call{1} verify_ll.
call{2} verifytw_ll.
skip => /> *; smt(size_map).
qed.

(* ==========================================================================
   THEOREM D.1 (multi-instance WOTS+C d-EU-naCMA), paper 2022/778 App D.
   The multi-instance two-term bound, composed from the two game-hops (linear
   real arithmetic), under the target-count hypothesis (`c <= p_tgts`) and the
   encode bridge (`encb`) — the multi-instance analogues of C.2's hypotheses.
   The WOTS-TW term is the LOCAL d-EU-naCMA game M_EUF_NACMA_WOTSTW_L (over the
   S-TCR collection); connecting it to MM45's repo `MEUFGCMA_WOTSTWESNPRF` black
   box is the deferred FC<->STCRC_WC.Col unification.
   CORRECTED 2026-08-18: this line said "(D1_bridge_WOTSTW below)".  There is no
   such lemma BELOW -- the name occurs nowhere else in this file.  It DOES exist,
   at WOTS_C_Bridge.ec:433 (was :391 -- that file's own status-correction note
   moved it; anchor on the NAME, not the number), in a downstream file that
   requires this one, that is
   absent from closure-c10-split.txt, and that does not compile at r2026.02.
   See the file header for the measurement.  Nothing in THIS file discharges the
   unification, so the bound below is over the LOCAL WOTS-TW game only.
   ========================================================================== *)
lemma D1_MEUFNACMA_WOTSC
  (A <: Adv_MnaCMA_WOTSC{-R_multi_STCRC, -R_multi_WOTSTW, -G0_MULTI,
                         -STCRC_WC.O_STCRC_Default, -STCRC_WC.Col.O_THFC_Default}) &m :
    c <= p_tgts =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    Pr[M_EUF_NACMA_WOTSC_L(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
  <=   Pr[STCRC_WC.S_TCR_C(R_multi_STCRC(A),
                           STCRC_WC.O_STCRC_Default,
                           STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
     + Pr[M_EUF_NACMA_WOTSTW_L(R_multi_WOTSTW(A),
                               STCRC_WC.Col.O_THFC_Default).main() @ &m : res].
proof.
  move=> le_c_ptgts encb.
  have h1 := D1_hop1 A &m le_c_ptgts.
  have h2 := D1_hop2 A &m encb.
  smt().
qed.
