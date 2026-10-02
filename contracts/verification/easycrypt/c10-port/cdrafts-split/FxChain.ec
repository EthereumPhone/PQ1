(* ==========================================================================
   fx_chain_wip.ec  --  THE +C FX-CHAIN GAME MODULES + HOP-1 (Orig -> PRFPRF).

   ROLE.  This file is the +C analog of MM45's FS chain (FV-SPHINCSPLUS-EC/
   proofs/SPHINCS_PLUS.ec:1726-2571): it builds the shared +C FX-chain game
   modules (FS keygens, FS signing oracle, the PRFPRF / NPRFPRF games) and
   proves hop-1, the materialization fold

       Pr[EUFCMA_C10(F).main() @ &m : res]
       = Pr[EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF(F).main() @ &m : res],

   the +C analog of MM45's Eqv_EUF_CMA_SPHINCSPLUSTW_Orig_FSPRFPRF
   (SPHINCS_PLUS.ec:2243-2571).  The capstone's admitted hop1
   (sphincs_c10_capstone_concrete_wip.ec, `p_prfprf`) is exactly this equality.

   ==========================================================================
   THE +C DELTAS (vs MM45 :1726-2571) -- the established +C modelling decisions:

     (1) MESSAGE KEY: `mk <$ dcond dmkey (good_fors m)` FRESH PER QUERY in the
         FS oracle (NOT `mk <- mkg ms m`, NOT an mmap random function).  This is
         the +C idealisation already present in SPHINCS_PLUS_C10.sign and in
         V_C.O_CMA_C (rtop_c_soundness_wip.ec:347), so hop-1 carries NO mkg/RF
         reasoning: the SAME draw is on both sides and couples by a single
         `rnd`.  Consequently `ms` (mseed) is dead key material, kept only for
         sk-shape parity with MM45 (and the capstone's sk_t).
     (2) FORS sign in the FS oracle is CUBE-based:
           FTWES.FL_FORS_ES_NPRF.sign((skFORS, ps, <trhftype ad>), cm)  and
           FTWES.FL_FORS_ES_NPRF.gen_pkFORS(skFORS, ps, <ad>);
         the scheme side is SEED-based (the FTWES.FL_FORS_ES family).  Hop-1 is the
         skg-derived materialization fold between them.
     (3) HT sign in the FS oracle is CUBE-based:
           FL_SL_XMSS_MT_C_ES_NPRF.sign((skWOTStd, ps, ad), pkFORS, idx);
         the scheme side is the seed-based FL_SL_XMSS_MT_C_ES.sign.  Both are
         DETERMINISTIC given their inputs (the WOTS+C counter is the total op
         `grindC`, WOTS_C_Scheme.ec:56 -- no counter sampling to couple).
     (4) VERIFY in the FS games is the +C-faithful SPHINCS_PLUS_C10.verify
         (good_fors m mk /\ size sigHT = d /\ root' = root /\ allOkC, via
         FL_SL_XMSS_MT_C_ES.root_from_sigC) -- IDENTICAL on both sides of
         hop-1, so the verify tail is a plain `sim`.
     (5) FS-game sk shape: MM45's `mseed * skFORS list list * skWOTS list
         list list * pseed` at the +C types (`FTWES.skFORS` =
         FTWES.DBLLKTL subtype for the FORS cube; `skWOTS` from
         FSSLXMTWES.WTWES for the WOTS cube).

   ==========================================================================
   PROOF ARCHITECTURE (why hop-1 at +C is SHORTER than MM45 :2243-2571).

   MM45's hop-1 is one monolithic inline relational sync.  Here every signer
   involved is DETERMINISTIC (delta 1 makes the only sampling the shared mk
   draw; deltas 2-3 are deterministic), so the support equivalences are proved
   via CLOSED FORMS (phoare = 1%r), then consumed one-sided (`call{1}` /
   `call{2}`) and equated by pure list/op rewriting under the skg-cube
   coupling:

     * SEED closed forms:  fors_leaves_op / fors_sig_op / genpk_seed_cf /
       leaves_sspsad_cf / htsign_seed_cf   (ports of sphincs_c10_scheme_wip.ec
       :764-896 + rtop_c_soundness_wip.ec :608-787 structure).
     * CUBE closed forms:  genleaves_cf / fors_sign_cube_cf / genpkfors_cf /
       leaves_cf / nprf_sign_cf   (ports of rtop_c_soundness_wip.ec :631-935,
       which are unrequireable lowercase and therefore re-derived here).
     * The packed support equiv Eqv_C10_sign_FSbody is the +C analog of MM45's
       Eqv_SPHINCS_PLUS_S_sign (SPHINCS_PLUS.ec:1908-1989):  the seed-based
       SPHINCS_PLUS_C10.sign equals the materialized-cube FS oracle sign under
       the skg-cube coupling.  (MM45's own S-sign differs from its scheme only
       in the FORS pk recompute; SPHINCS_PLUS_C10.sign is ALREADY in that
       S-shape -- it calls gen_pkFORS directly -- so the +C support equiv is
       precisely the seed-vs-cube fold, with no pkFORS round-trip leg.)
     * Hop-1's keygen prefix is MM45's nested one-sided while{2} cube-coupling
       block (:2257-2390), ported with the +C FTWES.DBLLKTL / DBLL subtypes.

   ==========================================================================
   PROVENANCE / INLINING.  `good_fors`, the DSSC clone, SPHINCS_PLUS_C10 and
   EUFCMA_C10 are copied VERBATIM from sphincs_c10_scheme_wip.ec (:120-251) --
   that file is lowercase and hence un-requireable; inlining is the
   established pattern (cf. the capstone's good_clone inline and
   rtop_c_soundness_wip.ec's R_top_C inline).  The closed-form helper scripts
   are ports of the cited proven scripts (same reason).

   ==========================================================================
   HONEST LEDGER  --  updated as the file grows (see bottom for the gate).

   DEFINITIONS (sections 1-6):
     * good_fors / DSSC / SPHINCS_PLUS_C10 / EUFCMA_C10        [verbatim copy]
     * SPHINCS_PLUS_C10_FS.{keygen_prf_c, keygen_nprf_c, verify_c}
     * O_CMA_SPHINCSPLUSTWC_FS : SOracle_CMA_C (+ init/fresh/nr_queries)
     * EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF / _NPRFPRF

   PROOFS:
     * support closed forms + support equiv Eqv_C10_sign_FSbody  [PROVEN 0-admit]
     * hop-1 Eqv_EUFCMA_C10_FSPRFPRFC + Pr_EUFCMA_C10_FSPRFPRFC  [PROVEN 0-admit]

   GATE RECORD (2026-07-22, adversarially audited PASS/HONEST):
     bash ec-certify.sh drafts/fx_chain_wip.ec
       => compile=OK  admit-tactics=0  axiom-decls=0  => CERTIFIED-0-ADMIT
     Canaries REJECTED by the gate: ={res} -> res{1}=!res{2}; Pr `=` -> `<`;
     htsign_seed_cf size res = d -> d+1.  Statements diffed vs MM45 (verbatim
     modulo the documented +C deltas); scheme copy diffed verbatim vs
     sphincs_c10_scheme_wip.ec; no new axioms.
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder IntDiv.
require import DList DMap FMap.
require import BinaryTrees MerkleTrees.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
(* SINGLE-SOURCE SEAM (2026-07-24): good_fors + the V_C game module
   (EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V) now live ONCE in RtopCSoundness (the lower
   +C layer, no DSSC/scheme).  Requiring it here (was: byte-copied inline) makes
   the hop-4 (this file) / hop-6 (RtopCSoundness) V_C the SAME module, so the
   capstone's final linear combination bridges p_vf across the two files by
   module identity, not byte-equality.  The 7 divergent proof-internal helpers
   (fidx / genpkfors_cf{,_h} / nprf_sign_cf{,_h} / wotsc_sign_cf_h / genpkfors_ll)
   remain locally defined below and SHADOW RtopCSoundness's same-named helpers
   (EasyCrypt rebinds, verified); they never reach the capstone goal. *)
require import RtopCSoundness.
require DigitalSignatures.
require import BitEncoding. import BS2Int BitChunking.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.
import FTWES.DBLLKTL.
import DigestBlock.
import IntOrder.

(* good_fors -- SINGLE-SOURCED, inherited from RtopCSoundness (was an inline
   byte-copy here; deleted 2026-07-24, diff-confirmed byte-identical to
   RtopCSoundness's op good_fors so every downstream use is unchanged). *)

(* --------------------------------------------------------------------------
   FRESH DigitalSignatures clone at the +C signature type -- VERBATIM copy of
   sphincs_c10_scheme_wip.ec:132-138 (sig_t = sigSPHINCSPLUSTWC; sk_t stays
   MM45's skSPHINCSPLUSTW).  Everything below stays DSSC.-qualified because
   `require import SPHINCS_PLUS` already pulled the OLD DSS.Stateless names
   into scope.
   -------------------------------------------------------------------------- *)
clone DigitalSignatures as DSSC with
  type pk_t  <- pkSPHINCSPLUSTW,
  type sk_t  <- skSPHINCSPLUSTW,
  type msg_t <- msg,
  type sig_t <- sigSPHINCSPLUSTWC

  proof *.

(* --------------------------------------------------------------------------
   THE CONCRETE SPHINCS+C10 SCHEME -- VERBATIM copy of sphincs_c10_scheme_wip.ec
   :143-238 (the hop-1 LHS object).  See that file's header for the +C
   substitution rationale; summary: seed-based sk (ms, ss, ps) as MM45; sign
   draws the +C conditioned message key FRESH, then runs the SEED-based FORS
   (FTWES.FL_FORS_ES.sign / gen_pkFORS) and the SEED-based +C hypertree
   (FL_SL_XMSS_MT_C_ES.sign); verify is the +C-faithful 4-conjunct gate.
   -------------------------------------------------------------------------- *)
module SPHINCS_PLUS_C10 : DSSC.Stateless.Scheme = {
  proc keygen() : pkSPHINCSPLUSTW * skSPHINCSPLUSTW = {
    var ad : adrs;
    var ms : mseed;
    var ss : sseed;
    var ps : pseed;
    var root : dgstblock;
    var pk : pkSPHINCSPLUSTW;
    var sk : skSPHINCSPLUSTW;

    ad <- adz;

    ms <$ dmseed;
    ss <$ dsseed;
    ps <$ dpseed;

    (* +C subst (ii): +C hypertree root (seed-based real FL_SL_XMSS_MT_C_ES). *)
    root <@ FL_SL_XMSS_MT_C_ES.gen_root(ss, ps, ad);

    pk <- (root, ps);
    sk <- (ms, ss, ps);

    return (pk, sk);
  }

  proc sign(sk : skSPHINCSPLUSTW, m : msg) : sigSPHINCSPLUSTWC = {
    var ms : mseed;
    var ss : sseed;
    var ps : pseed;
    var ad : adrs;
    var mk : mkey;
    var sigFORSTW : FTWES.sigFORSTW;
    var cm : FTWES.msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var pkFORS : FTWES.pkFORS;
    var sigHT : sigFLSLXMSSMTTWC;

    (ms, ss, ps) <- sk;

    ad <- adz;

    (* +C subst (i): the C10 conditioned message-key draw (grinding model). *)
    mk <$ dcond dmkey (good_fors m);

    (cm, idx) <- FTWES.mco mk m;

    (tidx, kpidx) <- edivz (Index.val idx) l';

    (* FORS branch at the MM45 FTWES shape, SEED-based (real skg keys). *)
    sigFORSTW <@ FTWES.FL_FORS_ES.sign((ss, ps,
                   set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);

    pkFORS <@ FTWES.FL_FORS_ES.gen_pkFORS(ss, ps,
                   set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

    (* +C subst (ii): +C hypertree signature (seed-based real). *)
    sigHT <@ FL_SL_XMSS_MT_C_ES.sign((ss, ps, ad), pkFORS, idx);

    return (mk, sigFORSTW, sigHT);
  }

  proc verify(pk : pkSPHINCSPLUSTW, m : msg, s : sigSPHINCSPLUSTWC) : bool = {
    var root, root' : dgstblock;
    var ps : pseed;
    var mk : mkey;
    var sigFORSTW : FTWES.sigFORSTW;
    var sigHT : sigFLSLXMSSMTTWC;
    var ad : adrs;
    var cm : FTWES.msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var pkFORS : FTWES.pkFORS;
    var allOkC : bool;

    (root, ps) <- pk;
    (mk, sigFORSTW, sigHT) <- s;

    ad <- adz;

    (cm, idx) <- FTWES.mco mk m;

    (tidx, kpidx) <- edivz (Index.val idx) l';

    pkFORS <@ FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW(sigFORSTW, cm, ps,
                   set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

    (* +C hypertree root reconstruction + per-layer constant-sum gate. *)
    (root', allOkC) <@ FL_SL_XMSS_MT_C_ES.root_from_sigC(pkFORS, sigHT, idx, ps, ad);

    (* Mirror V_C is_valid (rtop_c_soundness_wip.ec:451). *)
    return good_fors m mk /\ size sigHT = d /\ root' = root /\ allOkC;
  }
}.

(* The generic EUF_CMA game at the concrete scheme -- VERBATIM copy of
   sphincs_c10_scheme_wip.ec:250-251. *)
module EUFCMA_C10 (F : Adv_EUFCMA_C) =
  DSSC.Stateless.EUF_CMA(SPHINCS_PLUS_C10, F, DSSC.Stateless.O_CMA_Default).

(* ==========================================================================
   SECTION 4 -- THE FS (pregenerated-secret-key) SCHEME MODULE, +C.

   Port of MM45 SPHINCS_PLUS_FS (SPHINCS_PLUS.ec:1726-1874).  Both keygens
   materialize the FORS cube (nr_trees 0 x l' x k x t) and the WOTS cube
   (d x nr_trees(layer) x l' x len); `keygen_prf_c` derives every element by
   `skg ss (ps, <address>)` (the PRF side), `keygen_nprf_c` samples every
   element uniformly `<$ ddgstblock` (the NPRF side).  Both compute the public
   root from the top-most WOTS tree EXACTLY as the +C NPRF hypertree keygen
   does (FL_SL_XMSS_MT_C_ES_NPRF.keygen, XmssmtCC_All.ec:199-202): leaves via
   FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad, root via val_bt_trh at the
   trhxtype address -- so keygen_nprf_c's (root, WOTS cube) coincides with the
   V-game key material (rtop_c_soundness_wip.ec:394-415) that hop-2/hop-3
   target.
   ========================================================================== *)
module SPHINCS_PLUS_C10_FS = {
  proc keygen_prf_c() : pkSPHINCSPLUSTW * (mseed * FTWES.skFORS list list * skWOTS list list list * pseed) = {
    var ad : adrs;
    var ms : mseed;
    var ss : sseed;
    var ps : pseed;
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORScube : dgstblock list list;
    var skFORSlp : FTWES.skFORS list;
    var skFORSnt : FTWES.skFORS list list;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var root : dgstblock;
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * FTWES.skFORS list list * skWOTS list list list * pseed;

    ad <- adz;

    ms <$ dmseed;
    ss <$ dsseed;
    ps <$ dpseed;

    (* FORS cube, skg-derived at trhftype addresses (MM45 :1752-1767). *)
    skFORSnt <- [];
    while (size skFORSnt < nr_trees 0) {
      skFORSlp <- [];
      while (size skFORSlp < l') {
        skFORScube <- [];
        while (size skFORScube < k) {
          skFORSet <- [];
          while (size skFORSet < t) {
            skFORS_ele <- skg ss (ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSlp)) 0 (size skFORScube * t + size skFORSet));
            skFORSet <- rcons skFORSet skFORS_ele;
          }
          skFORScube <- rcons skFORScube skFORSet;
        }
        skFORSlp <- rcons skFORSlp (FTWES.DBLLKTL.insubd skFORScube);
      }
      skFORSnt <- rcons skFORSnt skFORSlp;
    }

    (* WOTS cube, skg-derived at chtype chain addresses (MM45 :1769-1784). *)
    skWOTStd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        while (size skWOTSlp < l') {
          skWOTS <- [];
          while (size skWOTS < len) {
            skWOTS_ele <- skg ss (ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) (size skWOTS)) 0);
            skWOTS <- rcons skWOTS skWOTS_ele;
          }
          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
    }

    (* Root from the top WOTS tree, +C NPRF-style (XmssmtCC_All.ec:199-202). *)
    skWOTSlp <- nth witness (nth witness skWOTStd (d - 1)) 0;
    leaves <@ FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);
    root <- val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);

    pk <- (root, ps);
    sk <- (ms, skFORSnt, skWOTStd, ps);

    return (pk, sk);
  }

  proc keygen_nprf_c() : pkSPHINCSPLUSTW * (mseed * FTWES.skFORS list list * skWOTS list list list * pseed) = {
    var ad : adrs;
    var ms : mseed;
    var ss : sseed;
    var ps : pseed;
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORScube : dgstblock list list;
    var skFORSlp : FTWES.skFORS list;
    var skFORSnt : FTWES.skFORS list list;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var root : dgstblock;
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * FTWES.skFORS list list * skWOTS list list list * pseed;

    ad <- adz;

    ms <$ dmseed;
    ss <$ dsseed;
    ps <$ dpseed;

    (* FORS cube, uniformly sampled (MM45 :1824-1839; same raw draw shape as
       V_C's keygen cube, rtop_c_soundness_wip.ec:394-410). *)
    skFORSnt <- [];
    while (size skFORSnt < nr_trees 0) {
      skFORSlp <- [];
      while (size skFORSlp < l') {
        skFORScube <- [];
        while (size skFORScube < k) {
          skFORSet <- [];
          while (size skFORSet < t) {
            skFORS_ele <$ ddgstblock;
            skFORSet <- rcons skFORSet skFORS_ele;
          }
          skFORScube <- rcons skFORScube skFORSet;
        }
        skFORSlp <- rcons skFORSlp (FTWES.DBLLKTL.insubd skFORScube);
      }
      skFORSnt <- rcons skFORSnt skFORSlp;
    }

    (* WOTS cube, uniformly sampled (MM45 :1841-1856). *)
    skWOTStd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        while (size skWOTSlp < l') {
          skWOTS <- [];
          while (size skWOTS < len) {
            skWOTS_ele <$ ddgstblock;
            skWOTS <- rcons skWOTS skWOTS_ele;
          }
          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
    }

    skWOTSlp <- nth witness (nth witness skWOTStd (d - 1)) 0;
    leaves <@ FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);
    root <- val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);

    pk <- (root, ps);
    sk <- (ms, skFORSnt, skWOTStd, ps);

    return (pk, sk);
  }

  (* +C-faithful verify: the REAL scheme's verify (delta 4) -- the +C analog of
     MM45's `proc verify = SPHINCS_PLUS.verify` (SPHINCS_PLUS.ec:1873). *)
  proc verify_c = SPHINCS_PLUS_C10.verify
}.

(* ==========================================================================
   SECTION 5 -- THE FS SIGNING ORACLE, +C.

   Port of MM45 O_CMA_SPHINCSPLUSTWFS_PRF (SPHINCS_PLUS.ec:1991-2050) with the
   +C deltas (1)-(3):  the message key is drawn FRESH per query from
   `dcond dmkey (good_fors m)` (delta 1 -- byte-identical to the scheme's own
   draw, so hop-1 couples it by one `rnd`; identical to V_C.O_CMA_C.sign,
   rtop_c_soundness_wip.ec:347-365, plus the MM45-style init/fresh/nr_queries
   that V_C's oracle does not carry).
   ========================================================================== *)
module O_CMA_SPHINCSPLUSTWC_FS : SOracle_CMA_C = {
  var sk : mseed * FTWES.skFORS list list * skWOTS list list list * pseed
  var qs : msg list

  proc init(sk_init : mseed * FTWES.skFORS list list * skWOTS list list list * pseed) : unit = {
    sk <- sk_init;
    qs <- [];
  }

  proc sign(m : msg) : sigSPHINCSPLUSTWC = {
    var ms : mseed;
    var skFORS : FTWES.skFORS;
    var pkFORS : FTWES.pkFORS;
    var skFORSnt : FTWES.skFORS list list;
    var skWOTStd : skWOTS list list list;
    var ps : pseed;
    var ad : adrs;
    var mk : mkey;
    var cm : FTWES.msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var sigFORSTW : FTWES.sigFORSTW;
    var sigHT : sigFLSLXMSSMTTWC;

    (ms, skFORSnt, skWOTStd, ps) <- sk;

    ad <- adz;

    (* +C delta 1: fresh conditioned draw (NOT mkg, NOT an mmap RF). *)
    mk <$ dcond dmkey (good_fors m);

    (cm, idx) <- FTWES.mco mk m;

    (tidx, kpidx) <- edivz (Index.val idx) l';

    skFORS <- nth witness (nth witness skFORSnt tidx) kpidx;

    (* +C delta 2: cube-based FORS sign + pk recompute. *)
    sigFORSTW <@ FTWES.FL_FORS_ES_NPRF.sign((skFORS, ps,
                     set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);

    pkFORS <@ FTWES.FL_FORS_ES_NPRF.gen_pkFORS(skFORS, ps,
                     set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

    (* +C delta 3: cube-based +C hypertree sign. *)
    sigHT <@ FL_SL_XMSS_MT_C_ES_NPRF.sign((skWOTStd, ps, ad), pkFORS, idx);

    qs <- rcons qs m;

    return (mk, sigFORSTW, sigHT);
  }

  proc fresh(m : msg) : bool = {
    return ! (m \in qs);
  }

  proc nr_queries() : int = {
    return size qs;
  }
}.

(* ==========================================================================
   SECTION 6 -- THE FS EUF-CMA GAMES, +C.

   Ports of MM45 EUF_CMA_SPHINCSPLUSTWFS_PRFPRF / _NPRFPRF (SPHINCS_PLUS.ec
   :2110-2157):  same main, with the +C FS keygens / oracle / verify.
   ========================================================================== *)
module EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF (A : Adv_EUFCMA_C) = {
  proc main() : bool = {
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * FTWES.skFORS list list * skWOTS list list list * pseed;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTWC;
    var is_valid, is_fresh : bool;

    (pk, sk) <@ SPHINCS_PLUS_C10_FS.keygen_prf_c();

    O_CMA_SPHINCSPLUSTWC_FS.init(sk);

    (m', sig') <@ A(O_CMA_SPHINCSPLUSTWC_FS).forge(pk);

    is_valid <@ SPHINCS_PLUS_C10_FS.verify_c(pk, m', sig');
    is_fresh <@ O_CMA_SPHINCSPLUSTWC_FS.fresh(m');

    return is_valid /\ is_fresh;
  }
}.

module EUF_CMA_SPHINCSPLUSTWC_FS_NPRFPRF (A : Adv_EUFCMA_C) = {
  proc main() : bool = {
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * FTWES.skFORS list list * skWOTS list list list * pseed;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTWC;
    var is_valid, is_fresh : bool;

    (pk, sk) <@ SPHINCS_PLUS_C10_FS.keygen_nprf_c();

    O_CMA_SPHINCSPLUSTWC_FS.init(sk);

    (m', sig') <@ A(O_CMA_SPHINCSPLUSTWC_FS).forge(pk);

    is_valid <@ SPHINCS_PLUS_C10_FS.verify_c(pk, m', sig');
    is_fresh <@ O_CMA_SPHINCSPLUSTWC_FS.fresh(m');

    return is_valid /\ is_fresh;
  }
}.

(* ==========================================================================
   SECTION 7 -- CLOSED-FORM SUPPORT ASSETS.

   Every signer in hop-1 is deterministic (only the shared mk draw is
   sampled), so the seed-vs-cube support equiv is built from per-procedure
   closed forms (phoare = 1%r), consumed one-sided and equated under the
   skg-cube coupling.  Script provenance:
     * seed FORS leaves/sign traces -- sphincs_c10_scheme_wip.ec:764-896
       (fors_genleaves_closed / fors_sign_trace / fors_lfidx_bound, verbatim
       ports; that file is unrequireable lowercase).
     * cube FORS leaves/pk traces   -- rtop_c_soundness_wip.ec:850-935
       (genleaves_cf_h / genpkfors_cf_h, near-verbatim ports).
     * HT cube sign closed form     -- rtop_c_soundness_wip.ec:608-799
       (pkwots_cf_h / wotsc_sign_cf_h / leaves_cf_h / nprf_sign_cf_h ports).
     * HT seed sign closed form     -- NEW, mirrored on the cube one with
       gen_skWOTS (skg) replacing the cube nth (same structure as
       nprf_sign_cf_h).
   ========================================================================== *)

(* ---- (7.A) FORS SEED closed forms (port of sphincs_c10_scheme_wip.ec). ---- *)

(* The seed-side FORS leaves closed form (sphincs_c10_scheme_wip.ec:764). *)
op fors_leaves_op (ss0:sseed) (ps0:pseed) (ad0:adrs) (idxt0:int) : dgstblock list =
  mkseq (fun (j:int) => f ps0 (set_thtbidx ad0 0 (idxt0*t+j))
                          (DigestBlock.val (skg ss0 (ps0, set_thtbidx ad0 0 (idxt0*t+j))))) t.

lemma fors_genleaves_closed (idxt0:int) (ss0:sseed) (ps0:pseed) (ad0:adrs) :
  hoare[FTWES.FL_FORS_ES.gen_leaves_single_tree :
    idxt=idxt0 /\ ss=ss0 /\ ps=ps0 /\ ad=ad0 ==> res = fors_leaves_op ss0 ps0 ad0 idxt0].
proof.
proc.
while (idxt=idxt0 /\ ss=ss0 /\ ps=ps0 /\ ad=ad0 /\ size leaves <= t
       /\ leaves = mkseq (fun (j:int) => f ps0 (set_thtbidx ad0 0 (idxt0*t+j))
                            (DigestBlock.val (skg ss0 (ps0, set_thtbidx ad0 0 (idxt0*t+j))))) (size leaves)).
+ wp; skip => /> &hr szle lvsdef ltt.
  rewrite size_rcons; split; 1: smt().
  by rewrite {1}lvsdef mkseqS 1:size_ge0.
wp; skip => />; split; 1: by rewrite mkseq0 /=; smt(ge2_t).
move=> leaves negg szle lvsdef.
have szt : size leaves = t by smt(ge2_t).
by rewrite /fors_leaves_op {1}lvsdef szt.
qed.

lemma fors_leaves_ll : islossless FTWES.FL_FORS_ES.gen_leaves_single_tree.
proof. proc; while (true) (t - size leaves); auto; smt(size_rcons ge2_t). qed.

(* The FORS honest-signature closed form: k trees, tree i signs message-slice
   lfidx i with skg secret + honest auth path over the tree's leaves
   (sphincs_c10_scheme_wip.ec:787). *)
op fors_sig_op (ss0:sseed) (ps0:pseed) (ad0:adrs) (m0:FTWES.msgFORSTW)
   : (dgstblock * FTWES.apFORSTW) list =
  mkseq (fun (i:int) =>
    let lfidx = bs2int (rev (take a (drop (a*i) (FTWES.BLKAL.val m0)))) in
    (skg ss0 (ps0, set_thtbidx ad0 0 (i*t+lfidx)),
     FTWES.cons_ap_trh ps0 ad0 (list2tree (fors_leaves_op ss0 ps0 ad0 i)) lfidx i)) k.

(* The per-tree FORS message index lands in [0,t)
   (sphincs_c10_scheme_wip.ec:796). *)
lemma fors_lfidx_bound (mv : FTWES.msgFORSTW) (sr : int) :
  0 <= sr < k =>
  0 <= bs2int (rev (take a (drop (a * sr) (FTWES.BLKAL.val mv)))) < t.
proof.
move=> [ge0_sr ltk_sr].
split; first exact bs2int_ge0.
move=> _.
have szr : size (rev (take a (drop (a * sr) (FTWES.BLKAL.val mv)))) = a.
- rewrite size_rev size_take 2:size_drop 3:FTWES.BLKAL.valP; 1,2: smt(ge1_a size_ge0).
  have hb : a <= a * (k - sr) by rewrite -{1}(mulr1 a) IntOrder.ler_wpmul2l; smt().
  have hr : a * (k - sr) = k * a - a * sr by ring.
  smt().
have hle := bs2int_le2Xs (rev (take a (drop (a * sr) (FTWES.BLKAL.val mv)))).
have ht : t = 2 ^ a by rewrite /t.
rewrite ht; rewrite szr in hle; exact hle.
qed.

(* Seed FORS sign emits exactly the fors_sig_op closed form
   (sphincs_c10_scheme_wip.ec:864, verbatim port). *)
lemma fors_sign_trace (ssv:sseed)(psv:pseed)(adv:adrs)(mv:FTWES.msgFORSTW) :
  hoare[FTWES.FL_FORS_ES.sign :
    sk = (ssv,psv,adv) /\ m = mv ==> FTWES.DBAPKL.val res = fors_sig_op ssv psv adv mv].
proof.
proc.
sp.
while (ss = ssv /\ ps = psv /\ ad = adv /\ m = mv /\ 0 <= size sig <= k
       /\ sig = mkseq (fun (i:int) =>
            let lfidx = bs2int (rev (take a (drop (a*i) (FTWES.BLKAL.val mv)))) in
            (skg ssv (psv, set_thtbidx adv 0 (i*t+lfidx)),
             FTWES.cons_ap_trh psv adv (list2tree (fors_leaves_op ssv psv adv i)) lfidx i)) (size sig)).
+ wp; exlim (size sig) => szs.
  call (fors_genleaves_closed szs ssv psv adv); wp; skip.
  move=> &hr [hszs [[hss [hps [had [hm [hb sigdef]]]]] guard]] /=.
  split; first smt().
  move=> junk lv heq.
  have key : rcons sig{hr}
       (skg ss{hr} (ps{hr}, set_thtbidx ad{hr} 0 (size sig{hr} * t + bs2int (rev (take a (drop (a * size sig{hr}) (FTWES.BLKAL.val m{hr})))))),
        FTWES.cons_ap_trh ps{hr} ad{hr} (list2tree lv) (bs2int (rev (take a (drop (a * size sig{hr}) (FTWES.BLKAL.val m{hr}))))) (size sig{hr}))
     = mkseq (fun (i:int) => let lfidx = bs2int (rev (take a (drop (a*i) (FTWES.BLKAL.val mv)))) in
              (skg ssv (psv, set_thtbidx adv 0 (i*t+lfidx)),
               FTWES.cons_ap_trh psv adv (list2tree (fors_leaves_op ssv psv adv i)) lfidx i)) (size sig{hr} + 1).
  - by rewrite mkseqS 1:size_ge0 /= -sigdef heq hszs hss hps had hm.
  smt(size_rcons).
skip => &m hpre; split; last first.
+ move=> sig0 hnlt hinv.
  have szk : size sig0 = k by smt().
  have hs0 : sig0 = fors_sig_op ssv psv adv mv by rewrite hinv /fors_sig_op szk.
  have hsz : size (fors_sig_op ssv psv adv mv) = k by rewrite /fors_sig_op size_mkseq; smt(ge1_k).
  by rewrite hs0 FTWES.DBAPKL.insubdK.
+ have hsig : sig{m} = [] by smt().
  rewrite hsig mkseq0 /=; smt(ge1_k).
qed.

lemma fors_sign_ll : islossless FTWES.FL_FORS_ES.sign.
proof.
proc; while (true) (k - size sig).
+ by move=> z; wp; call fors_leaves_ll; auto; smt(size_rcons).
by auto; smt(ge1_k).
qed.

(* Packaged seed-side FORS sign closed form (phoare = 1%r, one-sided-call
   ready). *)
lemma fors_sign_seed_cf (ssv:sseed)(psv:pseed)(adv:adrs)(mv:FTWES.msgFORSTW) :
  phoare[FTWES.FL_FORS_ES.sign :
    sk = (ssv,psv,adv) /\ m = mv ==> FTWES.DBAPKL.val res = fors_sig_op ssv psv adv mv] = 1%r.
proof. conseq fors_sign_ll (fors_sign_trace ssv psv adv mv) => //. qed.

(* Seed-side gen_pkFORS closed form -- NEW, mirrored on the cube-side
   genpkfors_cf_h (rtop_c_soundness_wip.ec:875) with the proven seed leaves
   closed form fors_genleaves_closed replacing genleaves_cf_h. *)
lemma genpk_seed_cf_h (ss0:sseed) (ps0:pseed) (ad0:adrs) :
  hoare[FTWES.FL_FORS_ES.gen_pkFORS :
        ss = ss0 /\ ps = ps0 /\ ad = ad0
        ==> res = trco ps0 (set_kpidx (set_typeidx ad0 trcotype) (FTWES.get_kpidx ad0))
                    (flatten (map DigestBlock.val
                       (mkseq (fun (u : int) =>
                          FTWES.val_bt_trh ps0 ad0
                            (list2tree (fors_leaves_op ss0 ps0 ad0 u)) u) k)))].
proof.
proc.
wp.
while (   ss = ss0 /\ ps = ps0 /\ ad = ad0
       /\ roots = mkseq (fun (u : int) =>
             FTWES.val_bt_trh ps0 ad0 (list2tree (fors_leaves_op ss0 ps0 ad0 u)) u) (size roots)
       /\ 0 <= size roots <= k).
+ wp.
  exists* roots; elim* => rts0.
  call (fors_genleaves_closed (size rts0) ss0 ps0 ad0).
  wp; skip => /> eqrts ge0 lek guard.
  rewrite size_rcons mkseqS 1:size_ge0 /=.
  rewrite -eqrts /=.
  smt().
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge1_k).
move => rts hnlt hrts hge hle.
have szk : size rts = k by smt().
by rewrite {1}hrts szk.
qed.

lemma fors_genpk_ll : islossless FTWES.FL_FORS_ES.gen_pkFORS.
proof.
proc; wp; while (true) (k - size roots).
+ by move=> z; wp; call fors_leaves_ll; auto; smt(size_rcons).
by auto; smt(ge1_k).
qed.

lemma genpk_seed_cf (ss0:sseed) (ps0:pseed) (ad0:adrs) :
  phoare[FTWES.FL_FORS_ES.gen_pkFORS :
        ss = ss0 /\ ps = ps0 /\ ad = ad0
        ==> res = trco ps0 (set_kpidx (set_typeidx ad0 trcotype) (FTWES.get_kpidx ad0))
                    (flatten (map DigestBlock.val
                       (mkseq (fun (u : int) =>
                          FTWES.val_bt_trh ps0 ad0
                            (list2tree (fors_leaves_op ss0 ps0 ad0 u)) u) k)))] = 1%r.
proof. conseq fors_genpk_ll (genpk_seed_cf_h ss0 ps0 ad0) => //. qed.

(* ---- (7.B) FORS CUBE closed forms (ports of rtop_c_soundness_wip.ec). ---- *)

(* The cube-side FORS leaves closed form. *)
op fors_leaves_op_cube (skF0:FTWES.skFORS) (ps0:pseed) (ad0:adrs) (idxt0:int) : dgstblock list =
  mkseq (fun (j:int) => f ps0 (set_thtbidx ad0 0 (idxt0*t+j))
             (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skF0) idxt0) j))) t.

lemma genleaves_cube_cf_h (idxt0 : int) (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) :
  hoare[FTWES.FL_FORS_ES_NPRF.gen_leaves_single_tree :
        idxt = idxt0 /\ skFORS = skF /\ ps = ps0 /\ ad = ad0
        ==> res = fors_leaves_op_cube skF ps0 ad0 idxt0].
proof.
proc.
while (   idxt = idxt0 /\ skFORS = skF /\ ps = ps0 /\ ad = ad0
       /\ leaves = mkseq (fun (i : int) =>
             f ps0 (set_thtbidx ad0 0 (idxt0 * t + i))
               (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skF) idxt0) i))) (size leaves)
       /\ 0 <= size leaves <= t).
+ wp; skip => /> &hr eqlvs ge0 _ ltt.
  rewrite size_rcons {1}eqlvs mkseqS 1:size_ge0 /=.
  by rewrite -/t; smt(size_rcons size_ge0).
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge2_t).
move => lvs *.
have lvsE : lvs = mkseq (fun (i : int) =>
     f ps0 (set_thtbidx ad0 0 (idxt0 * t + i))
       (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skF) idxt0) i))) t by smt().
by rewrite lvsE.
qed.

lemma genleaves_cube_ll : islossless FTWES.FL_FORS_ES_NPRF.gen_leaves_single_tree.
proof.
proc; while (true) (t - size leaves).
+ move => z; auto; smt(size_rcons).
by auto; smt().
qed.

(* The cube-side FORS honest-signature closed form -- NEW, mirrored on
   fors_sign_trace with the cube nth replacing skg. *)
op fors_sig_op_cube (skF0:FTWES.skFORS) (ps0:pseed) (ad0:adrs) (m0:FTWES.msgFORSTW)
   : (dgstblock * FTWES.apFORSTW) list =
  mkseq (fun (i:int) =>
    let lfidx = bs2int (rev (take a (drop (a*i) (FTWES.BLKAL.val m0)))) in
    (nth witness (nth witness (FTWES.DBLLKTL.val skF0) i) lfidx,
     FTWES.cons_ap_trh ps0 ad0 (list2tree (fors_leaves_op_cube skF0 ps0 ad0 i)) lfidx i)) k.

lemma fors_sign_cube_trace (skFv:FTWES.skFORS)(psv:pseed)(adv:adrs)(mv:FTWES.msgFORSTW) :
  hoare[FTWES.FL_FORS_ES_NPRF.sign :
    sk = (skFv,psv,adv) /\ m = mv ==> FTWES.DBAPKL.val res = fors_sig_op_cube skFv psv adv mv].
proof.
proc.
sp.
while (skFORS = skFv /\ ps = psv /\ ad = adv /\ m = mv /\ 0 <= size sig <= k
       /\ sig = mkseq (fun (i:int) =>
            let lfidx = bs2int (rev (take a (drop (a*i) (FTWES.BLKAL.val mv)))) in
            (nth witness (nth witness (FTWES.DBLLKTL.val skFv) i) lfidx,
             FTWES.cons_ap_trh psv adv (list2tree (fors_leaves_op_cube skFv psv adv i)) lfidx i)) (size sig)).
+ wp; exlim (size sig) => szs.
  call (genleaves_cube_cf_h szs skFv psv adv); wp; skip.
  move=> &hr [hszs [[hskf [hps [had [hm [hb sigdef]]]]] guard]] /=.
  split; first smt().
  move=> junk lv heq.
  have key : rcons sig{hr}
       (nth witness (nth witness (FTWES.DBLLKTL.val skFORS{hr}) (size sig{hr})) (bs2int (rev (take a (drop (a * size sig{hr}) (FTWES.BLKAL.val m{hr}))))),
        FTWES.cons_ap_trh ps{hr} ad{hr} (list2tree lv) (bs2int (rev (take a (drop (a * size sig{hr}) (FTWES.BLKAL.val m{hr}))))) (size sig{hr}))
     = mkseq (fun (i:int) => let lfidx = bs2int (rev (take a (drop (a*i) (FTWES.BLKAL.val mv)))) in
              (nth witness (nth witness (FTWES.DBLLKTL.val skFv) i) lfidx,
               FTWES.cons_ap_trh psv adv (list2tree (fors_leaves_op_cube skFv psv adv i)) lfidx i)) (size sig{hr} + 1).
  - by rewrite mkseqS 1:size_ge0 /= -sigdef heq hszs hskf hps had hm.
  smt(size_rcons).
skip => &m hpre; split; last first.
+ move=> sig0 hnlt hinv.
  have szk : size sig0 = k by smt().
  have hs0 : sig0 = fors_sig_op_cube skFv psv adv mv by rewrite hinv /fors_sig_op_cube szk.
  have hsz : size (fors_sig_op_cube skFv psv adv mv) = k by rewrite /fors_sig_op_cube size_mkseq; smt(ge1_k).
  by rewrite hs0 FTWES.DBAPKL.insubdK.
+ have hsig : sig{m} = [] by smt().
  rewrite hsig mkseq0 /=; smt(ge1_k).
qed.

lemma fors_sign_cube_ll : islossless FTWES.FL_FORS_ES_NPRF.sign.
proof.
proc; while (true) (k - size sig).
+ by move=> z; wp; call genleaves_cube_ll; auto; smt(size_rcons).
by auto; smt(ge1_k).
qed.

lemma fors_sign_cube_cf (skFv:FTWES.skFORS)(psv:pseed)(adv:adrs)(mv:FTWES.msgFORSTW) :
  phoare[FTWES.FL_FORS_ES_NPRF.sign :
    sk = (skFv,psv,adv) /\ m = mv ==> FTWES.DBAPKL.val res = fors_sig_op_cube skFv psv adv mv] = 1%r.
proof. conseq fors_sign_cube_ll (fors_sign_cube_trace skFv psv adv mv) => //. qed.

(* Cube-side gen_pkFORS closed form (port of rtop_c_soundness_wip.ec:875-935). *)
lemma genpkfors_cf_h (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) :
  hoare[FTWES.FL_FORS_ES_NPRF.gen_pkFORS :
        skFORS = skF /\ ps = ps0 /\ ad = ad0
        ==> res = trco ps0 (set_kpidx (set_typeidx ad0 trcotype) (FTWES.get_kpidx ad0))
                    (flatten (map DigestBlock.val
                       (mkseq (fun (u : int) =>
                          FTWES.val_bt_trh ps0 ad0
                            (list2tree (fors_leaves_op_cube skF ps0 ad0 u)) u) k)))].
proof.
proc.
wp.
while (   skFORS = skF /\ ps = ps0 /\ ad = ad0
       /\ roots = mkseq (fun (u : int) =>
             FTWES.val_bt_trh ps0 ad0 (list2tree (fors_leaves_op_cube skF ps0 ad0 u)) u) (size roots)
       /\ 0 <= size roots <= k).
+ wp.
  exists* roots; elim* => rts0.
  call (genleaves_cube_cf_h (size rts0) skF ps0 ad0).
  wp; skip => /> eqrts ge0 lek guard.
  rewrite size_rcons mkseqS 1:size_ge0 /=.
  rewrite -eqrts /=.
  smt().
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge1_k).
move => rts hnlt hrts hge hle.
have szk : size rts = k by smt().
by rewrite {1}hrts szk.
qed.

lemma genpkfors_ll : islossless FTWES.FL_FORS_ES_NPRF.gen_pkFORS.
proof.
proc; wp; while (true) (k - size roots).
+ move => z; wp; call genleaves_cube_ll; auto; smt(size_rcons).
by auto; smt().
qed.

lemma genpkfors_cf (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) :
  phoare[FTWES.FL_FORS_ES_NPRF.gen_pkFORS :
        skFORS = skF /\ ps = ps0 /\ ad = ad0
        ==> res = trco ps0 (set_kpidx (set_typeidx ad0 trcotype) (FTWES.get_kpidx ad0))
                    (flatten (map DigestBlock.val
                       (mkseq (fun (u : int) =>
                          FTWES.val_bt_trh ps0 ad0
                            (list2tree (fors_leaves_op_cube skF ps0 ad0 u)) u) k)))] = 1%r.
proof. conseq genpkfors_ll (genpkfors_cf_h skF ps0 ad0) => //. qed.

(* ---- (7.C) HYPERTREE shared index fold + SEED closed forms. ---- *)

(* Shared layer-index fold (rtop_c_soundness_wip.ec:696, verbatim). *)
op fidx (idx0 : index) (j : int) : int * int =
  fold (fun (ijs : int * int) => edivz ijs.`1 l') (Index.val idx0, 0) j.

(* gen_skWOTS closed form: the len-loop accumulates the skg chain keys. *)
lemma genskwots_cf_h (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) :
  hoare[WOTS_TW_ES.gen_skWOTS :
        ss = ss0 /\ ps = ps0 /\ ad = ad0
        ==> res = DBLL.insubd (mkseq (fun (v : int) =>
                     skg ss0 (ps0, set_hidx (set_chidx ad0 v) 0)) len)].
proof.
proc.
while (   ss = ss0 /\ ps = ps0 /\ ad = ad0
       /\ skWOTS = mkseq (fun (v : int) => skg ss0 (ps0, set_hidx (set_chidx ad0 v) 0)) (size skWOTS)
       /\ 0 <= size skWOTS <= len).
+ wp; skip => /> &hr eqsk ge0 _ ltlen.
  rewrite size_rcons {1}eqsk mkseqS 1:size_ge0 /=.
  smt(size_rcons size_ge0).
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge2_len).
move => skw *.
have skwE : skw = mkseq (fun (v : int) => skg ss0 (ps0, set_hidx (set_chidx ad0 v) 0)) len by smt().
by rewrite skwE.
qed.

(* WOTS_TW_ES.pkWOTS_from_skWOTS closed form (seed-side ES module; body is
   byte-identical to the NPRF one, so this is pkwots_cf_h's script verbatim,
   rtop_c_soundness_wip.ec:608). *)
lemma pkwots_es_cf_h (skW : skWOTS) (ps0 : pseed) (ad0 : adrs) :
  hoare[WOTS_TW_ES.pkWOTS_from_skWOTS :
        skWOTS = skW /\ ps = ps0 /\ ad = ad0
        ==> DBLL.val res = mkseq (fun (v : int) =>
              cf ps0 (set_chidx ad0 v) 0 (w - 1) (DigestBlock.val (nth witness (DBLL.val skW) v))) len].
proof.
proc.
while (ps = ps0 /\ ad = ad0 /\ skWOTS = skW
       /\ pkWOTS = mkseq (fun (v : int) =>
            cf ps0 (set_chidx ad0 v) 0 (w - 1) (DigestBlock.val (nth witness (DBLL.val skW) v))) (size pkWOTS)
       /\ 0 <= size pkWOTS <= len).
+ wp; skip => /> &hr eqpk ge0 _ ltlen.
  rewrite size_rcons {1}eqpk mkseqS 1:size_ge0 /=.
  smt(size_rcons size_ge0).
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge2_len).
move => pkw *.
have pkwE : pkw = mkseq (fun (v : int) =>
     cf ps0 (set_chidx ad0 v) 0 (w - 1) (DigestBlock.val (nth witness (DBLL.val skW) v))) len by smt().
rewrite pkwE; apply DBLL.insubdK; rewrite size_mkseq; smt(ge2_len).
qed.

(* WOTS_TW_ES_NPRF.pkWOTS_from_skWOTS closed form (rtop_c_soundness_wip.ec:608,
   verbatim port). *)
lemma pkwots_cube_cf_h (skW : skWOTS) (ps0 : pseed) (ad0 : adrs) :
  hoare[WOTS_TW_ES_NPRF.pkWOTS_from_skWOTS :
        skWOTS = skW /\ ps = ps0 /\ ad = ad0
        ==> DBLL.val res = mkseq (fun (v : int) =>
              cf ps0 (set_chidx ad0 v) 0 (w - 1) (DigestBlock.val (nth witness (DBLL.val skW) v))) len].
proof.
proc.
while (ps = ps0 /\ ad = ad0 /\ skWOTS = skW
       /\ pkWOTS = mkseq (fun (v : int) =>
            cf ps0 (set_chidx ad0 v) 0 (w - 1) (DigestBlock.val (nth witness (DBLL.val skW) v))) (size pkWOTS)
       /\ 0 <= size pkWOTS <= len).
+ wp; skip => /> &hr eqpk ge0 _ ltlen.
  rewrite size_rcons {1}eqpk mkseqS 1:size_ge0 /=.
  smt(size_rcons size_ge0).
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge2_len).
move => pkw *.
have pkwE : pkw = mkseq (fun (v : int) =>
     cf ps0 (set_chidx ad0 v) 0 (w - 1) (DigestBlock.val (nth witness (DBLL.val skW) v))) len by smt().
rewrite pkwE; apply DBLL.insubdK; rewrite size_mkseq; smt(ge2_len).
qed.

(* WOTS_C_ES.sign closed form (rtop_c_soundness_wip.ec:631, verbatim port) --
   shared by the seed and cube hypertree signers (both call WOTS_C_ES.sign). *)
lemma wotsc_sign_cf_h (skW : skWOTS) (ps0 : pseed) (ad0 : adrs) (mm : dgstblock) :
  hoare[WOTS_C_ES.sign :
        sk = (skW, ps0, ad0) /\ m = mm
        ==> res.`2 = grindC ps0 ad0 mm
         /\ DBLL.val res.`1 = mkseq (fun (v : int) =>
              cf ps0 (set_chidx ad0 v) 0
                (BaseW.val (encode_msgWOTS_C ps0 ad0 mm (grindC ps0 ad0 mm)).[v])
                (DigestBlock.val (nth witness (DBLL.val skW) v))) len].
proof.
proc.
while (ps = ps0 /\ ad = ad0 /\ skWOTS = skW /\ counter = grindC ps0 ad0 mm
       /\ em = encode_msgWOTS_C ps0 ad0 mm (grindC ps0 ad0 mm)
       /\ sig = mkseq (fun (v : int) =>
            cf ps0 (set_chidx ad0 v) 0 (BaseW.val (encode_msgWOTS_C ps0 ad0 mm (grindC ps0 ad0 mm)).[v])
              (DigestBlock.val (nth witness (DBLL.val skW) v))) (size sig)
       /\ 0 <= size sig <= len).
+ wp; skip => /> &hr eqsig ge0 _ ltlen.
  rewrite size_rcons {1}eqsig mkseqS 1:size_ge0 /=.
  smt(size_rcons size_ge0).
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge2_len).
move => sig *.
have sigE : sig = mkseq (fun (v : int) =>
     cf ps0 (set_chidx ad0 v) 0 (BaseW.val (encode_msgWOTS_C ps0 ad0 mm (grindC ps0 ad0 mm)).[v])
       (DigestBlock.val (nth witness (DBLL.val skW) v))) len by smt().
rewrite sigE; apply DBLL.insubdK; rewrite size_mkseq; smt(ge2_len).
qed.

(* Seed-side hypertree closed-form ops: mirror rtop_c_soundness_wip.ec:699-724
   with `skg ss0 (ps0, <chain adrs>)` replacing the cube nth lookups. *)
op tree_leaves_s (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (lyr tr : int) : dgstblock list =
  mkseq (fun (u : int) =>
    pkco ps0 (set_kpidx (set_typeidx (set_ltidx ad0 lyr tr) pkcotype) u)
         (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
             cf ps0 (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 lyr tr) chtype) u) v) 0 (w - 1)
                (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 lyr tr) chtype) u) v) 0)))) len)))) l'.

op tree_root_s (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (lyr tr : int) : dgstblock =
  val_bt_trh ps0 (set_typeidx (set_ltidx ad0 lyr tr) trhxtype) (list2tree (tree_leaves_s ss0 ps0 ad0 lyr tr)).

op rt_cf_s (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) : msgFLSLXMSSMTTW =
  if j = 0 then m0 else tree_root_s ss0 ps0 ad0 (j - 1) (fidx idx0 j).`1.

op sig_cf_elem_s (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) : sigWOTS * cntr =
  let ti = (fidx idx0 j).`1 in
  let rt = rt_cf_s ss0 ps0 ad0 m0 idx0 j in
  let chad = set_kpidx (set_typeidx (set_ltidx ad0 j (ti %/ l')) chtype) (ti %% l') in
  (DBLL.insubd (mkseq (fun (v : int) =>
      cf ps0 (set_chidx chad v) 0 (BaseW.val (encode_msgWOTS_C ps0 chad rt (grindC ps0 chad rt)).[v])
         (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx chad v) 0)))) len),
   grindC ps0 chad rt).

op ap_cf_elem_s (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (idx0 : index) (j : int) : apFLXMSSTW =
  let ti = (fidx idx0 (j + 1)).`1 in
  let ki = (fidx idx0 (j + 1)).`2 in
  cons_ap_trh ps0 (set_typeidx (set_ltidx ad0 j ti) trhxtype) (list2tree (tree_leaves_s ss0 ps0 ad0 j ti)) ki.

(* leaves_from_sspsad closed form (seed): mirror of leaves_cf_h
   (rtop_c_soundness_wip.ec:660) with the gen_skWOTS skg form per leaf. *)
lemma leaves_sspsad_cf_h (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) :
  hoare[FL_SL_XMSS_MT_C_ES.leaves_from_sspsad :
        ss = ss0 /\ ps = ps0 /\ ad = ad0
        ==> res = mkseq (fun (u : int) =>
              pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
                   (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                       cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                          (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0)))) len)))) l'].
proof.
proc.
while (   ss = ss0 /\ ps = ps0 /\ ad = ad0
       /\ leaves = mkseq (fun (u : int) =>
              pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
                   (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                       cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                          (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0)))) len)))) (size leaves)
       /\ 0 <= size leaves <= l').
+ wp.
  exists* leaves; elim* => lvs.
  seq 1 : (   ss = ss0 /\ ps = ps0 /\ ad = ad0
           /\ skWOTS = DBLL.insubd (mkseq (fun (v : int) =>
                skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx ad0 chtype) (size lvs)) v) 0)) len)
           /\ leaves = lvs
           /\ lvs = mkseq (fun (u : int) =>
                    pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
                         (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                             cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                                (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0)))) len)))) (size lvs)
           /\ 0 <= size lvs < l').
  + call (genskwots_cf_h ss0 ps0 (set_kpidx (set_typeidx ad0 chtype) (size lvs))).
    by skip => />.
  call (pkwots_es_cf_h (DBLL.insubd (mkseq (fun (v : int) =>
             skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx ad0 chtype) (size lvs)) v) 0)) len))
                       ps0 (set_kpidx (set_typeidx ad0 chtype) (size lvs))).
  wp; skip => /> eqlvs ge0 ltlp result valpk.
  have hfl : flatten (map DigestBlock.val (DBLL.val result))
           = flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) (size lvs)) v) 0 (w - 1)
                   (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx ad0 chtype) (size lvs)) v) 0)))) len)).
  + rewrite valpk; do 2! congr.
    apply eq_in_mkseq => v rng_v /=.
    rewrite DBLL.insubdK.
    + by rewrite size_mkseq /=; smt(ge2_len).
    by rewrite nth_mkseq //.
  rewrite size_rcons {1}eqlvs mkseqS 1:size_ge0 /= hfl.
  split; [done | smt()].
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge2_lp).
move => lvs *.
have lvsE : lvs = mkseq (fun (u : int) =>
     pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
          (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
              cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                 (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0)))) len)))) l' by smt().
by rewrite lvsE.
qed.

lemma leaves_sspsad_cf (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) :
  phoare[FL_SL_XMSS_MT_C_ES.leaves_from_sspsad :
        ss = ss0 /\ ps = ps0 /\ ad = ad0
        ==> res = mkseq (fun (u : int) =>
              pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
                   (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                       cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                          (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0)))) len)))) l'] = 1%r.
proof. conseq leaves_ll (leaves_sspsad_cf_h ss0 ps0 ad0) => //. qed.

(* THE SEED-SIDE HYPERTREE SIGN closed form -- mirror of nprf_sign_cf_h
   (rtop_c_soundness_wip.ec:726-787) with gen_skWOTS (skg) replacing the cube
   extraction. *)
lemma htsign_seed_cf_h (ss0 : sseed) (ps0 : pseed) (ad0 : adrs)
                       (m0 : msgFLSLXMSSMTTW) (idx0 : index) :
  hoare[FL_SL_XMSS_MT_C_ES.sign :
        sk = (ss0, ps0, ad0) /\ m = m0 /\ idx = idx0
        ==> size res = d
         /\ (forall (j : int), 0 <= j < d =>
              nth witness res j
              = (sig_cf_elem_s ss0 ps0 ad0 m0 idx0 j, ap_cf_elem_s ss0 ps0 ad0 idx0 j))].
proof.
proc.
sp.
while (   ss = ss0 /\ ps = ps0 /\ ad = ad0
       /\ 0 <= size sapl <= d
       /\ (size sapl < d => tidx = (fidx idx0 (size sapl)).`1)
       /\ root = rt_cf_s ss0 ps0 ad0 m0 idx0 (size sapl)
       /\ (forall (j : int), 0 <= j < size sapl =>
            nth witness sapl j
            = (sig_cf_elem_s ss0 ps0 ad0 m0 idx0 j, ap_cf_elem_s ss0 ps0 ad0 idx0 j))).
+ sp 1.
  wp.
  exists* sapl, tidx, kpidx, root.
  elim* => sapl0 ti0 ki0 rt0.
  move => tidxlh.
  seq 1 : (   ss = ss0 /\ ps = ps0 /\ ad = ad0
           /\ skWOTS = DBLL.insubd (mkseq (fun (v : int) =>
                skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) v) 0)) len)
           /\ sapl = sapl0 /\ root = rt0 /\ tidx = ti0 /\ kpidx = ki0
           /\ (ti0, ki0) = edivz tidxlh l'
           /\ (size sapl0 < d => tidxlh = (fidx idx0 (size sapl0)).`1)
           /\ rt0 = rt_cf_s ss0 ps0 ad0 m0 idx0 (size sapl0)
           /\ 0 <= size sapl0 < d
           /\ (forall (j : int), 0 <= j < size sapl0 =>
                nth witness sapl0 j
                = (sig_cf_elem_s ss0 ps0 ad0 m0 idx0 j, ap_cf_elem_s ss0 ps0 ad0 idx0 j))).
  + call (genskwots_cf_h ss0 ps0 (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0)).
    by skip => />.
  call (leaves_sspsad_cf_h ss0 ps0 (set_ltidx ad0 (size sapl0) ti0)).
  call (wotsc_sign_cf_h (DBLL.insubd (mkseq (fun (v : int) =>
             skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) v) 0)) len))
                        ps0 (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) rt0).
  skip => /> edivzE fidxlh ge0 ltd saplINV result r2E r1E.
  have tidxlhE : tidxlh = (fidx idx0 (size sapl0)).`1 by apply fidxlh.
  have [tdivE tmodE] : ti0 = tidxlh %/ l' /\ ki0 = tidxlh %% l'.
  + by move: edivzE; rewrite /edivz; smt(ge2_lp).
  have fidxS1 : fidx idx0 (size sapl0 + 1) = (ti0, ki0).
  + rewrite (: fidx idx0 (size sapl0 + 1) = edivz (fidx idx0 (size sapl0)).`1 l').
    - by rewrite /fidx foldS 1:size_ge0 /=.
    by rewrite -tidxlhE -edivzE.
  have r1E'' : DBLL.val result.`1 = mkseq (fun (v : int) =>
       cf ps0 (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) v) 0
         (BaseW.val (encode_msgWOTS_C ps0 (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0)
                       (rt_cf_s ss0 ps0 ad0 m0 idx0 (size sapl0)) (grindC ps0 (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) (rt_cf_s ss0 ps0 ad0 m0 idx0 (size sapl0)))).[v])
         (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) v) 0)))) len.
  + rewrite r1E.
    apply eq_in_mkseq => v rng_v /=.
    have szgs : size (mkseq (fun (v0 : int) => skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) v0) 0)) len) = len.
    + by rewrite size_mkseq; smt(ge2_len).
    rewrite (DBLL.insubdK _ szgs).
    by rewrite nth_mkseq // /=.
  have r1E' : result.`1 = DBLL.insubd (mkseq (fun (v : int) =>
       cf ps0 (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) v) 0
         (BaseW.val (encode_msgWOTS_C ps0 (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0)
                       (rt_cf_s ss0 ps0 ad0 m0 idx0 (size sapl0)) (grindC ps0 (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) (rt_cf_s ss0 ps0 ad0 m0 idx0 (size sapl0)))).[v])
         (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) v) 0)))) len).
  + by rewrite -r1E'' DBLL.valKd.
  rewrite size_rcons.
  split; 1: smt(size_ge0).
  split; 1: by rewrite fidxS1.
  split.
  + have szne : (size sapl0 + 1 = 0) = false by smt(size_ge0).
    by rewrite /rt_cf_s szne /= fidxS1 /= /tree_root_s /tree_leaves_s.
  move => j ge0j ltj1.
  rewrite nth_rcons; case (j < size sapl0) => [ltj | /lezNgt gej].
  + by rewrite (saplINV j _) 1:/#.
  rewrite (: j = size sapl0) 1:/# /=.
  split.
  + rewrite r1E' r2E /sig_cf_elem_s /= -tidxlhE -tdivE -tmodE //.
  by rewrite /ap_cf_elem_s fidxS1 /= /tree_leaves_s.
skip => />.
split.
+ rewrite /fidx fold0 /=; smt(ge1_d).
move => sapl0 nlt ge0 led saplINV.
split; 1: smt().
move => j ge0j ltjd.
by rewrite saplINV 1:/#.
qed.

lemma htsign_seed_cf (ss0 : sseed) (ps0 : pseed) (ad0 : adrs)
                     (m0 : msgFLSLXMSSMTTW) (idx0 : index) :
  phoare[FL_SL_XMSS_MT_C_ES.sign :
        sk = (ss0, ps0, ad0) /\ m = m0 /\ idx = idx0
        ==> size res = d
         /\ (forall (j : int), 0 <= j < d =>
              nth witness res j
              = (sig_cf_elem_s ss0 ps0 ad0 m0 idx0 j, ap_cf_elem_s ss0 ps0 ad0 idx0 j))] = 1%r.
proof.
conseq sign_ll (htsign_seed_cf_h ss0 ps0 ad0 m0 idx0) => //.
qed.

(* ---- (7.D) HYPERTREE CUBE closed forms (ports of rtop_c_soundness_wip.ec
        :699-799, with the _c suffix to tell them from the seed _s forms). ---- *)

op tree_leaves_c (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (lyr tr : int) : dgstblock list =
  mkseq (fun (u : int) =>
    pkco ps0 (set_kpidx (set_typeidx (set_ltidx ad0 lyr tr) pkcotype) u)
         (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
             cf ps0 (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 lyr tr) chtype) u) v) 0 (w - 1)
                (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd0 lyr) tr) u)) v))) len)))) l'.

op tree_root_c (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (lyr tr : int) : dgstblock =
  val_bt_trh ps0 (set_typeidx (set_ltidx ad0 lyr tr) trhxtype) (list2tree (tree_leaves_c skWOTStd0 ps0 ad0 lyr tr)).

op rt_cf_c (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) : msgFLSLXMSSMTTW =
  if j = 0 then m0 else tree_root_c skWOTStd0 ps0 ad0 (j - 1) (fidx idx0 j).`1.

op sig_cf_elem_c (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) : sigWOTS * cntr =
  let ti = (fidx idx0 j).`1 in
  let rt = rt_cf_c skWOTStd0 ps0 ad0 m0 idx0 j in
  let chad = set_kpidx (set_typeidx (set_ltidx ad0 j (ti %/ l')) chtype) (ti %% l') in
  (DBLL.insubd (mkseq (fun (v : int) =>
      cf ps0 (set_chidx chad v) 0 (BaseW.val (encode_msgWOTS_C ps0 chad rt (grindC ps0 chad rt)).[v])
         (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd0 j) (ti %/ l')) (ti %% l'))) v))) len),
   grindC ps0 chad rt).

op ap_cf_elem_c (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (idx0 : index) (j : int) : apFLXMSSTW =
  let ti = (fidx idx0 (j + 1)).`1 in
  let ki = (fidx idx0 (j + 1)).`2 in
  cons_ap_trh ps0 (set_typeidx (set_ltidx ad0 j ti) trhxtype) (list2tree (tree_leaves_c skWOTStd0 ps0 ad0 j ti)) ki.

(* leaves_from_sklpsad closed form (rtop_c_soundness_wip.ec:660, verbatim port). *)
lemma leaves_cube_cf_h (skWl : skWOTS list) (ps0 : pseed) (ad0 : adrs) :
  hoare[FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad :
        skWOTSl = skWl /\ ps = ps0 /\ ad = ad0
        ==> res = mkseq (fun (u : int) =>
              pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
                   (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                       cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                          (DigestBlock.val (nth witness (DBLL.val (nth witness skWl u)) v))) len)))) l'].
proof.
proc.
while (   ps = ps0 /\ ad = ad0 /\ skWOTSl = skWl
       /\ leaves = mkseq (fun (u : int) =>
              pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
                   (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                       cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                          (DigestBlock.val (nth witness (DBLL.val (nth witness skWl u)) v))) len)))) (size leaves)
       /\ 0 <= size leaves <= l').
+ wp.
  exists* leaves; elim* => lvs.
  call (pkwots_cube_cf_h (nth witness skWl (size lvs)) ps0 (set_kpidx (set_typeidx ad0 chtype) (size lvs))).
  wp; skip => /> eqlvs ge0 lelp guard result valpk.
  rewrite size_rcons {1}eqlvs mkseqS 1:size_ge0 /=.
  split; last by smt().
  by congr; rewrite valpk.
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge2_lp).
move => lvs *.
have lvsE : lvs = mkseq (fun (u : int) =>
     pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
          (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
              cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                 (DigestBlock.val (nth witness (DBLL.val (nth witness skWl u)) v))) len)))) l' by smt().
by rewrite lvsE.
qed.

lemma leaves_cube_cf (skWl : skWOTS list) (ps0 : pseed) (ad0 : adrs) :
  phoare[FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad :
        skWOTSl = skWl /\ ps = ps0 /\ ad = ad0
        ==> res = mkseq (fun (u : int) =>
              pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
                   (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                       cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                          (DigestBlock.val (nth witness (DBLL.val (nth witness skWl u)) v))) len)))) l'] = 1%r.
proof. conseq leaves_sklpsad_ll (leaves_cube_cf_h skWl ps0 ad0) => //. qed.

(* THE CUBE-SIDE HYPERTREE SIGN closed form (rtop_c_soundness_wip.ec:726-799,
   verbatim port at the _c ops). *)
lemma nprf_sign_cf_h (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs)
                     (m0 : msgFLSLXMSSMTTW) (idx0 : index) :
  hoare[FL_SL_XMSS_MT_C_ES_NPRF.sign :
        sk = (skWOTStd0, ps0, ad0) /\ m = m0 /\ idx = idx0
        ==> size res = d
         /\ (forall (j : int), 0 <= j < d =>
              nth witness res j
              = (sig_cf_elem_c skWOTStd0 ps0 ad0 m0 idx0 j, ap_cf_elem_c skWOTStd0 ps0 ad0 idx0 j))].
proof.
proc.
sp.
while (   ps = ps0 /\ ad = ad0 /\ skWOTStd = skWOTStd0
       /\ 0 <= size sapl <= d
       /\ (size sapl < d => tidx = (fidx idx0 (size sapl)).`1)
       /\ root = rt_cf_c skWOTStd0 ps0 ad0 m0 idx0 (size sapl)
       /\ (forall (j : int), 0 <= j < size sapl =>
            nth witness sapl j
            = (sig_cf_elem_c skWOTStd0 ps0 ad0 m0 idx0 j, ap_cf_elem_c skWOTStd0 ps0 ad0 idx0 j))).
+ sp 3.
  wp.
  exists* skWOTSlp, skWOTS, sapl, tidx, kpidx, root.
  elim* => slp0 skw0 sapl0 ti0 ki0 rt0.
  move => tidxlh.
  call (leaves_cube_cf_h slp0 ps0 (set_ltidx ad0 (size sapl0) ti0)).
  call (wotsc_sign_cf_h skw0 ps0 (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) rt0).
  skip => /> edivzE ge0 led fidxlh saplINV guard result r2E r1E.
  have tidxlhE : tidxlh = (fidx idx0 (size sapl0)).`1 by apply fidxlh.
  have [tdivE tmodE] : ti0 = tidxlh %/ l' /\ ki0 = tidxlh %% l'.
  + by move: edivzE; rewrite /edivz; smt(ge2_lp).
  have fidxS1 : fidx idx0 (size sapl0 + 1) = (ti0, ki0).
  + rewrite (: fidx idx0 (size sapl0 + 1) = edivz (fidx idx0 (size sapl0)).`1 l').
    - by rewrite /fidx foldS 1:size_ge0 /=.
    by rewrite -tidxlhE -edivzE.
  have r1E' : result.`1 = DBLL.insubd (mkseq (fun (v : int) =>
       cf ps0 (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) v) 0
         (BaseW.val (encode_msgWOTS_C ps0 (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0)
                       (rt_cf_c skWOTStd0 ps0 ad0 m0 idx0 (size sapl0))
                       (grindC ps0 (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0)
                          (rt_cf_c skWOTStd0 ps0 ad0 m0 idx0 (size sapl0)))).[v])
         (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd0 (size sapl0)) ti0) ki0)) v))) len).
  + by rewrite -r1E DBLL.valKd.
  rewrite size_rcons.
  split; 1: smt(size_ge0).
  split; 1: by rewrite fidxS1.
  split.
  + have szne : (size sapl0 + 1 = 0) = false by smt(size_ge0).
    by rewrite /rt_cf_c szne /= fidxS1 /= /tree_root_c /tree_leaves_c.
  move => j ge0j ltj1.
  rewrite nth_rcons; case (j < size sapl0) => [ltj | /lezNgt gej].
  + by rewrite (saplINV j _) 1:/#.
  rewrite (: j = size sapl0) 1:/# /=.
  split.
  + rewrite r1E' r2E /sig_cf_elem_c /= -tidxlhE -tdivE -tmodE //.
  by rewrite /ap_cf_elem_c fidxS1 /= /tree_leaves_c.
skip => />.
split.
+ rewrite /fidx fold0 /=; smt(ge1_d).
move => sapl0 nlt ge0 led saplINV.
split; 1: smt().
move => j ge0j ltjd.
by rewrite saplINV 1:/#.
qed.

lemma nprf_sign_cf (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs)
                   (m0 : msgFLSLXMSSMTTW) (idx0 : index) :
  phoare[FL_SL_XMSS_MT_C_ES_NPRF.sign :
        sk = (skWOTStd0, ps0, ad0) /\ m = m0 /\ idx = idx0
        ==> size res = d
         /\ (forall (j : int), 0 <= j < d =>
              nth witness res j
              = (sig_cf_elem_c skWOTStd0 ps0 ad0 m0 idx0 j, ap_cf_elem_c skWOTStd0 ps0 ad0 idx0 j))] = 1%r.
proof.
conseq nprf_sign_ll (nprf_sign_cf_h skWOTStd0 ps0 ad0 m0 idx0) => //.
qed.

(* ==========================================================================
   SECTION 8 -- THE SUPPORT EQUIV (+C analog of MM45's Eqv_SPHINCS_PLUS_S_sign,
   SPHINCS_PLUS.ec:1908-1989).

   MM45's support lemma equates its seed-based scheme sign with a "spec" sign
   whose only delta is the FORS pk recompute (gen_pkFORS for
   pkFORS_from_sigFORSTW).  SPHINCS_PLUS_C10.sign is ALREADY in that S-shape,
   so the +C support equiv is precisely the SEED-vs-CUBE materialization fold:
   SPHINCS_PLUS_C10.sign (seed FORS/HT signers) equals the FS oracle sign
   (cube FORS/HT signers) under the skg-cube coupling.  Built from the Section
   7 closed forms; the per-index bounds come from `foldedivz`
   (FL_SL_XMSS_MT_ES.ec:785) + Index.valP.
   ========================================================================== *)

(* ---- (8.A) index-bound auxiliaries over the shared fold fidx. ---- *)

(* Powers of l' as powers of 2 (avoids re-deriving the exponent algebra). *)
lemma pow_l (j : int) : l' ^ j = 2 ^ (h' * j).
proof. by rewrite /l' -exprM. qed.

lemma pow_lS (j : int) : 0 <= j => l' ^ j * l' = l' ^ (j + 1).
proof.
move=> ge0j.
rewrite (pow_l j) (pow_l (j + 1)).
have -> : l' = l' ^ 1 by rewrite expr1.
rewrite (pow_l 1).
have e1 : 0 <= h' * j by rewrite mulr_ge0; smt(ge1_hp).
have e2 : 0 <= h' * 1 by smt(ge1_hp).
rewrite -(exprD_nneg 2 _ _ e1 e2).
congr; ring.
qed.

(* The tree index at layer j (1 <= j <= d) ranges over [0, nr_trees (j-1)). *)
lemma fidx_tree_bound (idx0 : index) (j : int) :
  1 <= j <= d => 0 <= (fidx idx0 j).`1 < nr_trees (j - 1).
proof.
move=> [ge1j lejd].
have lp0 : 0 < l' by smt(ge2_lp).
have ge0j : 0 <= j by smt().
have ge0lp : 0 <= l' by smt(ge2_lp).
have egt : 0 < l' ^ j by rewrite expr_gt0; smt(ge2_lp).
rewrite /fidx (foldedivz (Index.val idx0) l' j ge0j ge0lp) /=.
rewrite /nr_trees.
have -> : h' * (d - (j - 1) - 1) = h' * (d - j) by ring.
split.
+ by rewrite divz_ge0 1:egt /=; smt(Index.valP).
rewrite ltz_divLR 1:egt /=.
have -> : 2 ^ (h' * (d - j)) * l' ^ j = l.
+ rewrite (pow_l j).
  have e1 : 0 <= h' * (d - j) by rewrite mulr_ge0; smt(ge1_hp ge1_d).
  have e2 : 0 <= h' * j by rewrite mulr_ge0; smt(ge1_hp).
  rewrite -(exprD_nneg 2 _ _ e1 e2).
  rewrite /l /h.
  have -> : h' * (d - j) + h' * j = h' * d by ring.
  done.
smt(Index.valP).
qed.

(* The tree index INSIDE layer j (0 <= j < d) ranges over [0, nr_trees j). *)
lemma fidx_tidx_bound (idx0 : index) (j : int) :
  0 <= j < d => 0 <= (fidx idx0 j).`1 %/ l' < nr_trees j.
proof.
move=> [ge0j ltjd].
have lp0 : 0 < l' by smt(ge2_lp).
have ge0lp : 0 <= l' by smt(ge2_lp).
have egt : 0 < l' ^ j by rewrite expr_gt0; smt(ge2_lp).
have egtW : 0 <= l' ^ j by smt().
rewrite /fidx (foldedivz (Index.val idx0) l' j ge0j ge0lp) /=.
split.
+ rewrite divz_ge0 1:lp0 /=.
  by rewrite divz_ge0 1:egt /=; smt(Index.valP).
rewrite -(divz_mul (Index.val idx0) (l' ^ j) l' egtW).
rewrite (pow_lS j ge0j).
rewrite ltz_divLR 1:expr_gt0 /=; 1: smt(ge2_lp).
have -> : nr_trees j * l' ^ (j + 1) = l.
+ rewrite /nr_trees (pow_l (j + 1)).
  have e1 : 0 <= h' * (d - j - 1) by rewrite mulr_ge0; smt(ge1_hp ge1_d).
  have e2 : 0 <= h' * (j + 1) by rewrite mulr_ge0; smt(ge1_hp ge1_d).
  rewrite -(exprD_nneg 2 _ _ e1 e2).
  rewrite /l /h.
  have -> : h' * (d - j - 1) + h' * (j + 1) = h' * d by ring.
  done.
smt(Index.valP).
qed.

(* The keypair index inside layer j ranges over [0, l'). *)
lemma fidx_kpidx_bound (idx0 : index) (j : int) :
  0 <= j => 0 <= (fidx idx0 j).`1 %% l' < l'.
proof.
move=> ge0j.
have lp0 : 0 < l' by smt(ge2_lp).
have ge0lp : 0 <= l' by smt(ge2_lp).
have egt : 0 < l' ^ j by rewrite expr_gt0; smt(ge2_lp).
rewrite /fidx (foldedivz (Index.val idx0) l' j ge0j ge0lp) /=.
split; 2: by rewrite ltz_pmod.
by rewrite modz_ge0 1:/=; smt(ge2_lp).
qed.

(* ---- (8.B) op-level equalities under the cube couplings. ---- *)

(* The seed and cube FORS leaves closed forms coincide on a coupled FORS row. *)
lemma fors_leaves_s_eq_c (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (skF0 : FTWES.skFORS) (u0 : int) :
  (forall (u v : int), 0 <= u && u < k => 0 <= v && v < t =>
     nth witness (nth witness (FTWES.DBLLKTL.val skF0) u) v
     = skg ss0 (ps0, set_thtbidx ad0 0 (u * t + v))) =>
  0 <= u0 < k =>
  fors_leaves_op ss0 ps0 ad0 u0 = fors_leaves_op_cube skF0 ps0 ad0 u0.
proof.
move=> fcpl [ge0u ltku].
rewrite /fors_leaves_op /fors_leaves_op_cube.
apply eq_in_mkseq => v rng_v /=.
by rewrite (fcpl u0 v _ rng_v) 1:/=.
qed.

(* The seed and cube FORS signature closed forms coincide on a coupled row. *)
lemma fors_sig_op_s_eq_c (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (skF0 : FTWES.skFORS) (cm0 : FTWES.msgFORSTW) :
  (forall (u v : int), 0 <= u && u < k => 0 <= v && v < t =>
     nth witness (nth witness (FTWES.DBLLKTL.val skF0) u) v
     = skg ss0 (ps0, set_thtbidx ad0 0 (u * t + v))) =>
  fors_sig_op ss0 ps0 ad0 cm0 = fors_sig_op_cube skF0 ps0 ad0 cm0.
proof.
move=> fcpl.
rewrite /fors_sig_op /fors_sig_op_cube.
apply eq_in_mkseq => i rng_i /=.
have lfb : 0 <= bs2int (rev (take a (drop (a * i) (FTWES.BLKAL.val cm0)))) < t.
+ by apply fors_lfidx_bound; smt().
have h_i : 0 <= i && i < k by smt().
rewrite (fcpl i (bs2int (rev (take a (drop (a * i) (FTWES.BLKAL.val cm0))))) h_i lfb).
split; 1: done.
by rewrite (fors_leaves_s_eq_c ss0 ps0 ad0 skF0 i fcpl rng_i).
qed.

(* The seed and cube hypertree-tree-leaves closed forms coincide on a coupled
   WOTS tree. *)
lemma tree_leaves_s_eq_c (ss0 : sseed) (ps0 : pseed) (skWtd : skWOTS list list list) (lyr tr : int) :
  (forall (i j u v : int), 0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
     nth witness (DBLL.val (nth witness (nth witness (nth witness skWtd i) j) u)) v
     = skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)) =>
  0 <= lyr < d => 0 <= tr < nr_trees lyr =>
  tree_leaves_s ss0 ps0 adz lyr tr = tree_leaves_c skWtd ps0 adz lyr tr.
proof.
move=> wcpl [ge0lyr ltdlyr] [ge0tr ltnttr].
rewrite /tree_leaves_s /tree_leaves_c.
apply eq_in_mkseq => u rng_u /=.
do 3! congr.
apply eq_in_mkseq => v rng_v /=.
have h1 : 0 <= lyr && lyr < d by smt().
have h2 : 0 <= tr && tr < nr_trees lyr by smt().
by rewrite (wcpl lyr tr u v h1 h2 rng_u rng_v).
qed.

(* Hence the running roots coincide. *)
lemma rt_cf_s_eq_c (ss0 : sseed) (ps0 : pseed) (skWtd : skWOTS list list list)
                   (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) :
  (forall (i j u v : int), 0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
     nth witness (DBLL.val (nth witness (nth witness (nth witness skWtd i) j) u)) v
     = skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)) =>
  1 <= j <= d =>
  rt_cf_s ss0 ps0 adz m0 idx0 j = rt_cf_c skWtd ps0 adz m0 idx0 j.
proof.
move=> wcpl rng_j.
rewrite /rt_cf_s /rt_cf_c.
have ne0 : (j = 0) = false by smt().
rewrite ne0 /= /tree_root_s /tree_root_c.
do 2! congr.
have [ge0b ltb] := fidx_tree_bound idx0 j rng_j.
have hlyr : 0 <= j - 1 < d by smt().
have htr : 0 <= (fidx idx0 j).`1 < nr_trees (j - 1) by smt().
exact: (tree_leaves_s_eq_c ss0 ps0 skWtd (j - 1) (fidx idx0 j).`1 wcpl hlyr htr).
qed.

(* Hence the per-layer WOTS+C signature elements coincide. *)
lemma sig_cf_elem_s_eq_c (ss0 : sseed) (ps0 : pseed) (skWtd : skWOTS list list list)
                         (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) :
  (forall (i j u v : int), 0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
     nth witness (DBLL.val (nth witness (nth witness (nth witness skWtd i) j) u)) v
     = skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)) =>
  0 <= j < d =>
  sig_cf_elem_s ss0 ps0 adz m0 idx0 j = sig_cf_elem_c skWtd ps0 adz m0 idx0 j.
proof.
move=> wcpl rng_j.
rewrite /sig_cf_elem_s /sig_cf_elem_c /=.
have rte : rt_cf_s ss0 ps0 adz m0 idx0 j = rt_cf_c skWtd ps0 adz m0 idx0 j.
+ case (j = 0) => [-> | ne0] //=.
  apply rt_cf_s_eq_c => //; smt().
rewrite rte.
have h1 : 0 <= j && j < d by smt().
have h2 : 0 <= (fidx idx0 j).`1 %/ l' && (fidx idx0 j).`1 %/ l' < nr_trees j.
+ have hb := fidx_tidx_bound idx0 j rng_j; smt().
have h3 : 0 <= (fidx idx0 j).`1 %% l' && (fidx idx0 j).`1 %% l' < l'.
+ have hb := fidx_kpidx_bound idx0 j _; 1: smt(); smt().
split; 2: done.
congr.
apply eq_in_mkseq => v rng_v /=.
by rewrite (wcpl j ((fidx idx0 j).`1 %/ l') ((fidx idx0 j).`1 %% l') v h1 h2 h3 rng_v).
qed.

(* Hence the per-layer authentication paths coincide. *)
lemma ap_cf_elem_s_eq_c (ss0 : sseed) (ps0 : pseed) (skWtd : skWOTS list list list)
                        (idx0 : index) (j : int) :
  (forall (i j u v : int), 0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
     nth witness (DBLL.val (nth witness (nth witness (nth witness skWtd i) j) u)) v
     = skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)) =>
  0 <= j < d =>
  ap_cf_elem_s ss0 ps0 adz idx0 j = ap_cf_elem_c skWtd ps0 adz idx0 j.
proof.
move=> wcpl rng_j.
rewrite /ap_cf_elem_s /ap_cf_elem_c /=.
do 2! congr.
have [ge0b ltb] := fidx_tree_bound idx0 (j + 1) _; 1: smt().
apply tree_leaves_s_eq_c; 1: exact wcpl; smt().
qed.

(* nr_trees 0 * l' = l (the bottom-layer leaf count), used for FORS index
   routing bounds. *)
lemma nr_trees0_l : nr_trees 0 * l' = l.
proof.
rewrite /nr_trees.
have -> : d - 0 - 1 = d - 1 by ring.
rewrite /l /h.
have -> : l' = l' ^ 1 by rewrite expr1.
rewrite (pow_l 1).
have e1 : 0 <= h' * (d - 1) by rewrite mulr_ge0; smt(ge1_hp ge1_d).
have e2 : 0 <= h' * 1 by smt(ge1_hp).
rewrite -(exprD_nneg 2 _ _ e1 e2).
congr; ring.
qed.

(* The FORS tree/keypair indices from the message-compression index are in
   range (the (tidx, kpidx) <- edivz (val idx) l' routing). *)
lemma edivz_pair (x : int) : edivz x l' = (x %/ l', x %% l').
proof. by rewrite /edivz; smt(ge2_lp). qed.

lemma edivz_tidx_bound (ix : index) : 0 <= Index.val ix %/ l' < nr_trees 0.
proof.
have vP := Index.valP ix.
have lp0 : 0 < l' by smt(ge2_lp).
split.
+ by rewrite divz_ge0 1:lp0 /=; smt(Index.valP).
rewrite ltz_divLR 1:lp0 /=.
by rewrite nr_trees0_l; smt(Index.valP).
qed.

lemma edivz_kpidx_bound (ix : index) : 0 <= Index.val ix %% l' < l'.
proof.
have lp0 : 0 < l' by smt(ge2_lp).
split; 2: by rewrite ltz_pmod.
by rewrite modz_ge0 1:/=; smt(ge2_lp).
qed.

(* ---- (8.C) THE SUPPORT EQUIV.  The seed-based scheme sign equals the
   materialized-cube FS oracle sign, under the skg-cube coupling on the FS
   key material.  +C analog of MM45's Eqv_SPHINCS_PLUS_S_sign
   (SPHINCS_PLUS.ec:1908-1989); the cube coupling is EXACTLY the one hop-1's
   keygen prefix establishes (MM45 :2250-2256). ---- *)
lemma Eqv_C10_sign_FSbody (ms0 : mseed) (ss0 : sseed) (ps0 : pseed)
      (skFnt : FTWES.skFORS list list) (skWtd : skWOTS list list list) :
  equiv[SPHINCS_PLUS_C10.sign ~ O_CMA_SPHINCSPLUSTWC_FS.sign :
        ={m}
        /\ sk{1} = (ms0, ss0, ps0)
        /\ O_CMA_SPHINCSPLUSTWC_FS.sk{2} = (ms0, skFnt, skWtd, ps0)
        /\ (forall (i j u v : int),
               0 <= i && i < nr_trees 0 => 0 <= j && j < l' => 0 <= u && u < k => 0 <= v && v < t =>
               nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness skFnt i) j)) u) v
               = skg ss0 (ps0, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
        /\ (forall (i j u v : int),
               0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
               nth witness (DBLL.val (nth witness (nth witness (nth witness skWtd i) j) u)) v
               = skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))
        ==> ={res}].
proof.
proc.
(* Head: key extraction, ad, the SHARED conditioned mk draw (one coupled rnd),
   mco, edivz, and the RHS cube-row extraction. *)
seq 5 6 : (   ={m, mk, cm, idx, tidx, kpidx}
           /\ tidx{2} = Index.val idx{2} %/ l'
           /\ kpidx{2} = Index.val idx{2} %% l'
           /\ ss{1} = ss0 /\ ps{1} = ps0 /\ ps{2} = ps0
           /\ skWOTStd{2} = skWtd /\ skFORSnt{2} = skFnt
           /\ skFORS{2} = nth witness (nth witness skFnt tidx{2}) kpidx{2}
           /\ 0 <= tidx{2} < nr_trees 0 /\ 0 <= kpidx{2} < l'
           /\ ad{1} = adz /\ ad{2} = adz
           /\ (forall (i j u v : int),
                  0 <= i && i < nr_trees 0 => 0 <= j && j < l' => 0 <= u && u < k => 0 <= v && v < t =>
                  nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness skFnt i) j)) u) v
                  = skg ss0 (ps0, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
           /\ (forall (i j u v : int),
                  0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
                  nth witness (DBLL.val (nth witness (nth witness (nth witness skWtd i) j) u)) v
                  = skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))).
+ wp; rnd; wp; skip => &1 &2.
  move=> *.
  split; 2: split.
  - by [].
  - by smt().
  move=> mkL hsupp hsuppL.
  have hpe2 := edivz_pair (Index.val (FTWES.mco hsupp m{2}).`2).
  have hpe1 := edivz_pair (Index.val (FTWES.mco hsupp m{1}).`2).
  have hb2 := edivz_kpidx_bound (FTWES.mco hsupp m{2}).`2.
  have hb1 := edivz_tidx_bound (FTWES.mco hsupp m{2}).`2.
  split; smt().
(* FORS sign: seed closed form = cube closed form on the coupled row. *)
seq 1 0 : (#pre /\ FTWES.DBAPKL.val sigFORSTW{1}
             = fors_sig_op ss{1} ps{1}
                 (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1}) cm{1}).
+ exists* ss{1}, ps{1}, ad{1}, tidx{1}, kpidx{1}, cm{1}.
  elim* => ssv psv adv tiv kiv cmv.
  call{1} (fors_sign_seed_cf ssv psv (set_kpidx (set_tidx (set_typeidx adv trhftype) tiv) kiv) cmv).
  skip => /> &2 *.
seq 0 1 : (#pre
           /\ FTWES.DBAPKL.val sigFORSTW{1}
                = fors_sig_op ss{1} ps{1}
                    (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1}) cm{1}
           /\ FTWES.DBAPKL.val sigFORSTW{2}
                = fors_sig_op_cube skFORS{2} ps{2}
                    (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) tidx{2}) kpidx{2}) cm{2}).
+ exists* skFORS{2}, ps{2}, ad{2}, tidx{2}, kpidx{2}, cm{2}.
  elim* => skFv ps2v ad2v ti2v ki2v cm2v.
  call{2} (fors_sign_cube_cf skFv ps2v (set_kpidx (set_tidx (set_typeidx ad2v trhftype) ti2v) ki2v) cm2v).
  skip => /> &2 *; smt().
(* pure equate of the two closed forms via the row coupling *)
seq 0 0 : (#pre /\ ={sigFORSTW}).
+ skip => &1 &2; move=> [[hpre cf1] cf2].
  split; 1: smt().
  apply FTWES.DBAPKL.val_inj; rewrite cf1 cf2.
  have -> : ps{2} = ps{1} by smt().
  have -> : cm{2} = cm{1} by smt().
  have -> : tidx{2} = tidx{1} by smt().
  have -> : kpidx{2} = kpidx{1} by smt().
  have -> : ss{1} = ss0 by smt().
  have -> : ps{1} = ps0 by smt().
  have -> : ad{1} = adz by smt().
  have -> : ad{2} = adz by smt().
  have fcpl' : forall (u v : int), 0 <= u && u < k => 0 <= v && v < t =>
     nth witness (nth witness (FTWES.DBLLKTL.val skFORS{2}) u) v
     = skg ss0 (ps0, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{1}) kpidx{1}) 0 (u * t + v)).
  + move=> u v rng_u rng_v.
    have hskf : skFORS{2} = nth witness (nth witness skFnt tidx{1}) kpidx{1} by smt().
    have hb1 : 0 <= tidx{1} && tidx{1} < nr_trees 0 by smt().
    have hb2 : 0 <= kpidx{1} && kpidx{1} < l' by smt().
    rewrite hskf.
    by smt().
  exact: (fors_sig_op_s_eq_c ss0 ps0 (set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{1}) kpidx{1}) skFORS{2} cm{1} fcpl').

(* FORS pk recompute: seed = cube on the coupled row. *)
seq 1 0 : (#pre /\ pkFORS{1}
             = trco ps{1} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1}) trcotype)
                    (FTWES.get_kpidx (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1})))
                (flatten (map DigestBlock.val
                   (mkseq (fun (u : int) =>
                     FTWES.val_bt_trh ps{1} (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1})
                       (list2tree (fors_leaves_op ss{1} ps{1}
                         (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1}) u)) u) k)))).
+ exists* ss{1}, ps{1}, ad{1}, tidx{1}, kpidx{1}.
  elim* => ssv psv adv tiv kiv.
  call{1} (genpk_seed_cf ssv psv (set_kpidx (set_tidx (set_typeidx adv trhftype) tiv) kiv)).
  skip => /> &2 *.
seq 0 1 : (#pre
           /\ pkFORS{1}
                = trco ps{1} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1}) trcotype)
                       (FTWES.get_kpidx (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1})))
                   (flatten (map DigestBlock.val
                      (mkseq (fun (u : int) =>
                        FTWES.val_bt_trh ps{1} (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1})
                          (list2tree (fors_leaves_op ss{1} ps{1}
                            (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1}) u)) u) k)))
           /\ pkFORS{2}
                = trco ps{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) tidx{2}) kpidx{2}) trcotype)
                       (FTWES.get_kpidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) tidx{2}) kpidx{2})))
                   (flatten (map DigestBlock.val
                      (mkseq (fun (u : int) =>
                        FTWES.val_bt_trh ps{2} (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) tidx{2}) kpidx{2})
                          (list2tree (fors_leaves_op_cube skFORS{2} ps{2}
                            (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) tidx{2}) kpidx{2}) u)) u) k)))).
+ exists* skFORS{2}, ps{2}, ad{2}, tidx{2}, kpidx{2}.
  elim* => skFv ps2v ad2v ti2v ki2v.
  call{2} (genpkfors_cf skFv ps2v (set_kpidx (set_tidx (set_typeidx ad2v trhftype) ti2v) ki2v)).
  skip => /> &2 *; smt().
seq 0 0 : (#pre /\ ={pkFORS}).
+ skip => &1 &2; move=> [[hpre cf1] cf2].
  split; 1: smt().
  rewrite cf1 cf2.
  have -> : ps{2} = ps{1} by smt().
  have -> : tidx{2} = tidx{1} by smt().
  have -> : kpidx{2} = kpidx{1} by smt().
  have -> : ss{1} = ss0 by smt().
  have -> : ps{1} = ps0 by smt().
  have -> : ad{1} = adz by smt().
  have -> : ad{2} = adz by smt().
  have fcpl' : forall (u v : int), 0 <= u && u < k => 0 <= v && v < t =>
     nth witness (nth witness (FTWES.DBLLKTL.val skFORS{2}) u) v
     = skg ss0 (ps0, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{1}) kpidx{1}) 0 (u * t + v)).
  + move=> u v rng_u rng_v.
    have hskf : skFORS{2} = nth witness (nth witness skFnt tidx{1}) kpidx{1} by smt().
    have hb1 : 0 <= tidx{1} && tidx{1} < nr_trees 0 by smt().
    have hb2 : 0 <= kpidx{1} && kpidx{1} < l' by smt().
    rewrite hskf.
    by smt().
  do 3! congr.
  apply eq_in_mkseq => u rng_u /=.
  do 2! congr.
  exact: (fors_leaves_s_eq_c ss0 ps0 (set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{1}) kpidx{1}) skFORS{2} u fcpl' rng_u).

(* Hypertree sign: seed = cube per layer (sig_cf_elem / ap_cf_elem). *)
seq 1 0 : (#pre /\ size sigHT{1} = d
           /\ (forall (j : int), 0 <= j < d =>
                 nth witness sigHT{1} j
                 = (sig_cf_elem_s ss{1} ps{1} ad{1} pkFORS{1} idx{1} j,
                    ap_cf_elem_s ss{1} ps{1} ad{1} idx{1} j))).
+ exists* ss{1}, ps{1}, ad{1}, pkFORS{1}, idx{1}.
  elim* => ssv psv adv pkFv idxv.
  call{1} (htsign_seed_cf ssv psv adv pkFv idxv).
  skip => /> &2 *.
seq 0 1 : (#pre
           /\ size sigHT{1} = d
           /\ (forall (j : int), 0 <= j < d =>
                 nth witness sigHT{1} j
                 = (sig_cf_elem_s ss{1} ps{1} ad{1} pkFORS{1} idx{1} j,
                    ap_cf_elem_s ss{1} ps{1} ad{1} idx{1} j))
           /\ size sigHT{2} = d
           /\ (forall (j : int), 0 <= j < d =>
                 nth witness sigHT{2} j
                 = (sig_cf_elem_c skWOTStd{2} ps{2} ad{2} pkFORS{2} idx{2} j,
                    ap_cf_elem_c skWOTStd{2} ps{2} ad{2} idx{2} j))).
+ exists* skWOTStd{2}, ps{2}, ad{2}, pkFORS{2}, idx{2}.
  elim* => skWv ps2v ad2v pkF2v idx2v.
  call{2} (nprf_sign_cf skWv ps2v ad2v pkF2v idx2v).
  skip => /> &2 *; smt().
seq 0 0 : (#pre /\ ={sigHT}).
+ skip => &1 &2; move=> [hpre [sz1 [cf1 [sz2 cf2]]]].
  split; 1: smt().
  have hskw : skWOTStd{2} = skWtd by smt().
  apply (eq_from_nth witness); 1: by rewrite sz1 sz2.
  move=> j; rewrite sz1 => rng_j.
  rewrite (cf1 j rng_j) (cf2 j rng_j).
  have -> : ss{1} = ss0 by smt().
  have -> : ps{1} = ps0 by smt().
  have -> : ps{2} = ps0 by smt().
  have -> : ad{2} = ad{1} by smt().
  have -> : ad{1} = adz by smt().
  have -> : pkFORS{2} = pkFORS{1} by smt().
  have -> : idx{2} = idx{1} by smt().
  rewrite hskw.
  have hwc : (forall (i j u v : int), 0 <= i && i < d => 0 <= j && j < nr_trees i =>
               0 <= u && u < l' => 0 <= v && v < len =>
               nth witness (DBLL.val (nth witness (nth witness (nth witness skWtd i) j) u)) v
               = skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)) by smt().
  rewrite (sig_cf_elem_s_eq_c ss0 ps0 skWtd pkFORS{1} idx{1} j hwc rng_j).
  by rewrite (ap_cf_elem_s_eq_c ss0 ps0 skWtd idx{1} j hwc rng_j).

(* Tail: identical returns (RHS additionally appends qs, not in res). *)
wp; skip => &1 &2.
move=> *.
smt().
qed.


(* ---- (8.D) THE ORACLE-LEVEL WRAPPER: the +C analog of what hop-1's oracle
   `call` rule consumes for the sign case (MM45 discharges it inline with
   Eqv_SPHINCS_PLUS_S_sign + the body sync, SPHINCS_PLUS.ec:2394-2560).  The
   statement is the sign-proc case of hop-1's oracle invariant; the proof is
   the Section 8 support-equiv proof lifted over O_CMA_Default.sign's extra
   call layer (inline the SPHINCS_PLUS_C10.sign call, then the identical
   head / three one-sided-call blocks / tail, extended with the ={qs} and
   sk-relation invariant conjuncts). ---- *)
lemma Eqv_OsignC10_Default_FS :
  equiv[DSSC.Stateless.O_CMA_Default(SPHINCS_PLUS_C10).sign ~ O_CMA_SPHINCSPLUSTWC_FS.sign :
        ={arg}
        /\ ={qs}(DSSC.Stateless.O_CMA_Default, O_CMA_SPHINCSPLUSTWC_FS)
        /\ DSSC.Stateless.O_CMA_Default.sk{1}
             = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, DSSC.Stateless.O_CMA_Default.sk{1}.`2,
                DSSC.Stateless.O_CMA_Default.sk{1}.`3)
        /\ O_CMA_SPHINCSPLUSTWC_FS.sk{2}
             = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2,
                O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3, DSSC.Stateless.O_CMA_Default.sk{1}.`3)
        /\ (forall (i j u v : int),
               0 <= i && i < nr_trees 0 => 0 <= j && j < l' => 0 <= u && u < k => 0 <= v && v < t =>
               nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2 i) j)) u) v
               = skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
                   (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
        /\ (forall (i j u v : int),
               0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
               nth witness (DBLL.val (nth witness (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3 i) j) u)) v
               = skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
                   (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))
        ==> ={res}
            /\ ={qs}(DSSC.Stateless.O_CMA_Default, O_CMA_SPHINCSPLUSTWC_FS)
            /\ DSSC.Stateless.O_CMA_Default.sk{1}
                 = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, DSSC.Stateless.O_CMA_Default.sk{1}.`2,
                    DSSC.Stateless.O_CMA_Default.sk{1}.`3)
            /\ O_CMA_SPHINCSPLUSTWC_FS.sk{2}
                 = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2,
                    O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3, DSSC.Stateless.O_CMA_Default.sk{1}.`3)
            /\ (forall (i j u v : int),
                   0 <= i && i < nr_trees 0 => 0 <= j && j < l' => 0 <= u && u < k => 0 <= v && v < t =>
                   nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2 i) j)) u) v
                   = skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
                       (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
            /\ (forall (i j u v : int),
                   0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
                   nth witness (DBLL.val (nth witness (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3 i) j) u)) v
                   = skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
                       (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))].
proof.
proc.
inline{1} 1.
(* Head: key extraction, ad, the SHARED conditioned mk draw (one coupled rnd),
   mco, edivz, and the RHS cube-row extraction. *)
seq 7 6 : (   ={m, mk, cm, idx, tidx, kpidx}
           /\ tidx{2} = Index.val idx{2} %/ l'
           /\ kpidx{2} = Index.val idx{2} %% l'
           /\ ss{1} = DSSC.Stateless.O_CMA_Default.sk{1}.`2
           /\ ps{1} = DSSC.Stateless.O_CMA_Default.sk{1}.`3
           /\ ps{2} = DSSC.Stateless.O_CMA_Default.sk{1}.`3
           /\ skWOTStd{2} = O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3
           /\ skFORSnt{2} = O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2
           /\ skFORS{2} = nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2 tidx{2}) kpidx{2}
           /\ 0 <= tidx{2} < nr_trees 0 /\ 0 <= kpidx{2} < l'
           /\ ad{1} = adz /\ ad{2} = adz
           /\ ={qs}(DSSC.Stateless.O_CMA_Default, O_CMA_SPHINCSPLUSTWC_FS)
           /\ DSSC.Stateless.O_CMA_Default.sk{1}
                = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, DSSC.Stateless.O_CMA_Default.sk{1}.`2,
                   DSSC.Stateless.O_CMA_Default.sk{1}.`3)
           /\ O_CMA_SPHINCSPLUSTWC_FS.sk{2}
                = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2,
                   O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3, DSSC.Stateless.O_CMA_Default.sk{1}.`3)
           /\ (forall (i j u v : int),
                  0 <= i && i < nr_trees 0 => 0 <= j && j < l' => 0 <= u && u < k => 0 <= v && v < t =>
                  nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2 i) j)) u) v
                  = skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
                      (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
           /\ (forall (i j u v : int),
                  0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
                  nth witness (DBLL.val (nth witness (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3 i) j) u)) v
                  = skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
                      (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))).
+ wp; rnd; wp; skip => &1 &2.
  move=> *.
  split; 2: split.
  - by [].
  - by smt().
  move=> mkL hsupp hsuppL.
  have hpe2 := edivz_pair (Index.val (FTWES.mco hsupp m{2}).`2).
  have hpe1 := edivz_pair (Index.val (FTWES.mco hsupp m{1}).`2).
  have hb2 := edivz_kpidx_bound (FTWES.mco hsupp m{2}).`2.
  have hb1 := edivz_tidx_bound (FTWES.mco hsupp m{2}).`2.
  split; smt().
(* FORS sign: seed closed form = cube closed form on the coupled row. *)
seq 1 0 : (#pre /\ FTWES.DBAPKL.val sigFORSTW{1}
             = fors_sig_op ss{1} ps{1}
                 (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1}) cm{1}).
+ exists* ss{1}, ps{1}, ad{1}, tidx{1}, kpidx{1}, cm{1}.
  elim* => ssv psv adv tiv kiv cmv.
  call{1} (fors_sign_seed_cf ssv psv (set_kpidx (set_tidx (set_typeidx adv trhftype) tiv) kiv) cmv).
  skip => /> &2 *.
seq 0 1 : (#pre
           /\ FTWES.DBAPKL.val sigFORSTW{1}
                = fors_sig_op ss{1} ps{1}
                    (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1}) cm{1}
           /\ FTWES.DBAPKL.val sigFORSTW{2}
                = fors_sig_op_cube skFORS{2} ps{2}
                    (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) tidx{2}) kpidx{2}) cm{2}).
+ exists* skFORS{2}, ps{2}, ad{2}, tidx{2}, kpidx{2}, cm{2}.
  elim* => skFv ps2v ad2v ti2v ki2v cm2v.
  call{2} (fors_sign_cube_cf skFv ps2v (set_kpidx (set_tidx (set_typeidx ad2v trhftype) ti2v) ki2v) cm2v).
  skip => /> &2 *; smt().
(* pure equate of the two closed forms via the row coupling *)
seq 0 0 : (#pre /\ ={sigFORSTW}).
+ skip => &1 &2; move=> [[hpre cf1] cf2].
  split; 1: smt().
  apply FTWES.DBAPKL.val_inj; rewrite cf1 cf2.
  have -> : ps{2} = ps{1} by smt().
  have -> : cm{2} = cm{1} by smt().
  have -> : tidx{2} = tidx{1} by smt().
  have -> : kpidx{2} = kpidx{1} by smt().
  have -> : ss{1} = DSSC.Stateless.O_CMA_Default.sk{1}.`2 by smt().
  have -> : ps{1} = DSSC.Stateless.O_CMA_Default.sk{1}.`3 by smt().
  have -> : ad{1} = adz by smt().
  have -> : ad{2} = adz by smt().
  have fcpl' : forall (u v : int), 0 <= u && u < k => 0 <= v && v < t =>
     nth witness (nth witness (FTWES.DBLLKTL.val skFORS{2}) u) v
     = skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
         (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{1}) kpidx{1}) 0 (u * t + v)).
  + move=> u v rng_u rng_v.
    have hskf : skFORS{2} = nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2 tidx{1}) kpidx{1} by smt().
    have hb1 : 0 <= tidx{1} && tidx{1} < nr_trees 0 by smt().
    have hb2 : 0 <= kpidx{1} && kpidx{1} < l' by smt().
    rewrite hskf.
    by smt().
  exact: (fors_sig_op_s_eq_c DSSC.Stateless.O_CMA_Default.sk{1}.`2 DSSC.Stateless.O_CMA_Default.sk{1}.`3
            (set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{1}) kpidx{1}) skFORS{2} cm{1} fcpl').

(* FORS pk recompute: seed = cube on the coupled row. *)
seq 1 0 : (#pre /\ pkFORS{1}
             = trco ps{1} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1}) trcotype)
                    (FTWES.get_kpidx (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1})))
                (flatten (map DigestBlock.val
                   (mkseq (fun (u : int) =>
                     FTWES.val_bt_trh ps{1} (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1})
                       (list2tree (fors_leaves_op ss{1} ps{1}
                         (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1}) u)) u) k)))).
+ exists* ss{1}, ps{1}, ad{1}, tidx{1}, kpidx{1}.
  elim* => ssv psv adv tiv kiv.
  call{1} (genpk_seed_cf ssv psv (set_kpidx (set_tidx (set_typeidx adv trhftype) tiv) kiv)).
  skip => /> &2 *.
seq 0 1 : (#pre
           /\ pkFORS{1}
                = trco ps{1} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1}) trcotype)
                       (FTWES.get_kpidx (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1})))
                   (flatten (map DigestBlock.val
                      (mkseq (fun (u : int) =>
                        FTWES.val_bt_trh ps{1} (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1})
                          (list2tree (fors_leaves_op ss{1} ps{1}
                            (set_kpidx (set_tidx (set_typeidx ad{1} trhftype) tidx{1}) kpidx{1}) u)) u) k)))
           /\ pkFORS{2}
                = trco ps{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) tidx{2}) kpidx{2}) trcotype)
                       (FTWES.get_kpidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) tidx{2}) kpidx{2})))
                   (flatten (map DigestBlock.val
                      (mkseq (fun (u : int) =>
                        FTWES.val_bt_trh ps{2} (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) tidx{2}) kpidx{2})
                          (list2tree (fors_leaves_op_cube skFORS{2} ps{2}
                            (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) tidx{2}) kpidx{2}) u)) u) k)))).
+ exists* skFORS{2}, ps{2}, ad{2}, tidx{2}, kpidx{2}.
  elim* => skFv ps2v ad2v ti2v ki2v.
  call{2} (genpkfors_cf skFv ps2v (set_kpidx (set_tidx (set_typeidx ad2v trhftype) ti2v) ki2v)).
  skip => /> &2 *; smt().
seq 0 0 : (#pre /\ ={pkFORS}).
+ skip => &1 &2; move=> [[hpre cf1] cf2].
  split; 1: smt().
  rewrite cf1 cf2.
  have -> : ps{2} = ps{1} by smt().
  have -> : tidx{2} = tidx{1} by smt().
  have -> : kpidx{2} = kpidx{1} by smt().
  have -> : ss{1} = DSSC.Stateless.O_CMA_Default.sk{1}.`2 by smt().
  have -> : ps{1} = DSSC.Stateless.O_CMA_Default.sk{1}.`3 by smt().
  have -> : ad{1} = adz by smt().
  have -> : ad{2} = adz by smt().
  have fcpl' : forall (u v : int), 0 <= u && u < k => 0 <= v && v < t =>
     nth witness (nth witness (FTWES.DBLLKTL.val skFORS{2}) u) v
     = skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
         (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{1}) kpidx{1}) 0 (u * t + v)).
  + move=> u v rng_u rng_v.
    have hskf : skFORS{2} = nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2 tidx{1}) kpidx{1} by smt().
    have hb1 : 0 <= tidx{1} && tidx{1} < nr_trees 0 by smt().
    have hb2 : 0 <= kpidx{1} && kpidx{1} < l' by smt().
    rewrite hskf.
    by smt().
  do 3! congr.
  apply eq_in_mkseq => u rng_u /=.
  do 2! congr.
  exact: (fors_leaves_s_eq_c DSSC.Stateless.O_CMA_Default.sk{1}.`2 DSSC.Stateless.O_CMA_Default.sk{1}.`3
            (set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{1}) kpidx{1}) skFORS{2} u fcpl' rng_u).

(* Hypertree sign: seed = cube per layer (sig_cf_elem / ap_cf_elem). *)
seq 1 0 : (#pre /\ size sigHT{1} = d
           /\ (forall (j : int), 0 <= j < d =>
                 nth witness sigHT{1} j
                 = (sig_cf_elem_s ss{1} ps{1} ad{1} pkFORS{1} idx{1} j,
                    ap_cf_elem_s ss{1} ps{1} ad{1} idx{1} j))).
+ exists* ss{1}, ps{1}, ad{1}, pkFORS{1}, idx{1}.
  elim* => ssv psv adv pkFv idxv.
  call{1} (htsign_seed_cf ssv psv adv pkFv idxv).
  skip => /> &2 *.
seq 0 1 : (#pre
           /\ size sigHT{1} = d
           /\ (forall (j : int), 0 <= j < d =>
                 nth witness sigHT{1} j
                 = (sig_cf_elem_s ss{1} ps{1} ad{1} pkFORS{1} idx{1} j,
                    ap_cf_elem_s ss{1} ps{1} ad{1} idx{1} j))
           /\ size sigHT{2} = d
           /\ (forall (j : int), 0 <= j < d =>
                 nth witness sigHT{2} j
                 = (sig_cf_elem_c skWOTStd{2} ps{2} ad{2} pkFORS{2} idx{2} j,
                    ap_cf_elem_c skWOTStd{2} ps{2} ad{2} idx{2} j))).
+ exists* skWOTStd{2}, ps{2}, ad{2}, pkFORS{2}, idx{2}.
  elim* => skWv ps2v ad2v pkF2v idx2v.
  call{2} (nprf_sign_cf skWv ps2v ad2v pkF2v idx2v).
  skip => /> &2 *; smt().
seq 0 0 : (#pre /\ ={sigHT}).
+ skip => &1 &2; move=> [hpre [sz1 [cf1 [sz2 cf2]]]].
  split; 1: smt().
  have hskw : skWOTStd{2} = O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3 by smt().
  apply (eq_from_nth witness); 1: by rewrite sz1 sz2.
  move=> j; rewrite sz1 => rng_j.
  rewrite (cf1 j rng_j) (cf2 j rng_j).
  have -> : ss{1} = DSSC.Stateless.O_CMA_Default.sk{1}.`2 by smt().
  have -> : ps{1} = DSSC.Stateless.O_CMA_Default.sk{1}.`3 by smt().
  have -> : ps{2} = DSSC.Stateless.O_CMA_Default.sk{1}.`3 by smt().
  have -> : ad{2} = ad{1} by smt().
  have -> : ad{1} = adz by smt().
  have -> : pkFORS{2} = pkFORS{1} by smt().
  have -> : idx{2} = idx{1} by smt().
  rewrite hskw.
  have hwc : (forall (i j u v : int), 0 <= i && i < d => 0 <= j && j < nr_trees i =>
               0 <= u && u < l' => 0 <= v && v < len =>
               nth witness (DBLL.val (nth witness (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3 i) j) u)) v
               = skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
                   (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)) by smt().
  rewrite (sig_cf_elem_s_eq_c DSSC.Stateless.O_CMA_Default.sk{1}.`2 DSSC.Stateless.O_CMA_Default.sk{1}.`3 O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3 pkFORS{1} idx{1} j hwc rng_j).
  by rewrite (ap_cf_elem_s_eq_c DSSC.Stateless.O_CMA_Default.sk{1}.`2 DSSC.Stateless.O_CMA_Default.sk{1}.`3 O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3 idx{1} j hwc rng_j).

(* Tail: identical returns (RHS additionally appends qs, not in res). *)
wp; skip => &1 &2.
move=> *.
smt().
qed.
(* ==========================================================================
   SECTION 9 -- HOP-1: Orig -> PRFPRF.

   +C analog of MM45 Eqv_EUF_CMA_SPHINCSPLUSTW_Orig_FSPRFPRF (SPHINCS_PLUS.ec
   :2243-2571).  Proof shape:  seq 3 3 (keygen / oracle-init / forge) + a
   `sim` verify-fresh tail;  the keygen prefix is MM45's nested one-sided
   while{2} cube-coupling block (:2257-2390) at the +C FTWES.DBLLKTL / DBLL
   subtypes;  the oracle sign case is discharged by applying the Section 8.D
   wrapper equiv Eqv_OsignC10_Default_FS (MM45 instead inlines the sign-body
   work at :2397-2545 via `rewrite equiv` with Eqv_SPHINCS_PLUS_S_sign;  the
   +C support equiv Eqv_C10_sign_FSbody proves the same body-level fact and
   is retained for later hops);  the keygen suffix
   (root/pk/sk/init) couples the top-tree leaves via the Section 7 closed
   forms (MM45 :2560-2570's inline leaves sync, collapsed to the proven
   closed forms).
   ========================================================================== *)
lemma Eqv_EUFCMA_C10_FSPRFPRFC (F <: Adv_EUFCMA_C{-DSSC.Stateless.O_CMA_Default, -O_CMA_SPHINCSPLUSTWC_FS}) :
  equiv[EUFCMA_C10(F).main ~ EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF(F).main :
        ={glob F} ==> ={res}].
proof.
proc.
seq 3 3 : (   ={pk}
           /\ m{1} = m'{2}
           /\ sig{1} = sig'{2}
           /\ ={qs}(DSSC.Stateless.O_CMA_Default, O_CMA_SPHINCSPLUSTWC_FS)); 2: by sim.
inline{1} 1; inline{2} 1.
inline{1} FL_SL_XMSS_MT_C_ES.gen_root.
seq 4 8 : (   ={glob F, ad, ms, ss, ps}
           /\ ad{1} = adz
           /\ (forall (i j u v : int),
                 0 <= i && i < nr_trees 0 =>
                 0 <= j && j < l' =>
                 0 <= u && u < k =>
                 0 <= v && v < t =>
                 nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness skFORSnt{2} i) j)) u) v =
                 skg ss{1} (ps{1}, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
           /\ (forall (i j u v : int),
                0 <= i && i < d =>
                0 <= j && j < nr_trees i =>
                0 <= u && u < l' =>
                0 <= v && v < len =>
                nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v =
                skg ss{1} (ps{1}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))).
+ while{2} (    ad{2} = adz
            /\ (forall (i j u v : int),
                  0 <= i && i < size skWOTStd{2} =>
                  0 <= j && j < nr_trees i =>
                  0 <= u && u < l' =>
                  0 <= v && v < len =>
                  nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v =
                  skg ss{2} (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)))
           (d - size skWOTStd{2}).
  - move=> _ z.
    wp => /=.
    while (    ad = adz
           /\ (forall (j u v : int),
                 0 <= j && j < size skWOTSnt =>
                 0 <= u && u < l' =>
                 0 <= v && v < len =>
                 nth witness (DBLL.val (nth witness (nth witness skWOTSnt j) u)) v =
                 skg ss (ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz (size skWOTStd) j) chtype) u) v) 0)))
          (nr_trees (size skWOTStd) - size skWOTSnt).
    * move=> z'.
      wp => /=.
      while (    ad = adz
             /\ (forall (u v : int),
                   0 <= u && u < size skWOTSlp =>
                   0 <= v && v < len =>
                   nth witness (DBLL.val (nth witness skWOTSlp u)) v =
                   skg ss (ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz (size skWOTStd) (size skWOTSnt)) chtype) u) v) 0)))
            (l' - size skWOTSlp).
      + move=> z''.
        wp => /=.
        while (    ad = adz
               /\ (forall (v : int),
                     0 <= v && v < size skWOTS =>
                     nth witness skWOTS v =
                     skg ss (ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) v) 0))
               /\ size skWOTS <= len)
              (len - size skWOTS).
        - move=> z'''.
          by wp; skip => />; smt(nth_rcons size_rcons).
        wp; skip => /> &2 nthsklp ltl_szsklp.
        split => [| skw]; 2: split => [| /lezNgt gelen_szskw]; 1,2: smt(ge2_len).
        move=> nthskw lelen_skw; split; 2: by rewrite size_rcons /#.
        move=> u v ge0_u; rewrite nth_rcons ?size_rcons /= => ltsz1_u ge0_v ltlen_v.
        by case (u < size skWOTSlp{2}); smt(DBLL.insubdK DBLL.valP).
      wp; skip => /> &2 nthsknt ltl_szsknt.
      split => [/# | skwlp]; split => [/# | /lezNgt gent_szskwnt ?].
      by split; smt(nth_rcons size_rcons).
    wp; skip => /> &2 nthsktd ltd_szsktd.
    split => [/# | skwlp]; split => [/# | /lezNgt gent_szskwnt ?].
    by split; smt(nth_rcons size_rcons).
  wp => /=.
  while{2} (    ad{2} = adz
            /\ (forall (i j u v : int),
                 0 <= i && i < size skFORSnt{2} =>
                 0 <= j && j < l' =>
                 0 <= u && u < k =>
                 0 <= v && v < t =>
                 nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness skFORSnt{2} i) j)) u) v =
                 skg ss{2} (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v))))
           (nr_trees 0 - size skFORSnt{2}).
  - move => _ z.
    wp => /=.
    while (   ad = adz
           /\ (forall (j u v : int),
                 0 <= j && j < size skFORSlp =>
                 0 <= u && u < k =>
                 0 <= v && v < t =>
                 nth witness (nth witness (FTWES.DBLLKTL.val (nth witness skFORSlp j)) u) v =
                 skg ss (ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size skFORSnt)) j) 0 (u * t + v))))
          (l' - size skFORSlp).
    * move=> z'.
      wp => /=.
      while (   ad = adz
             /\ (forall (u v : int),
                   0 <= u && u < size skFORScube =>
                   0 <= v && v < t =>
                   nth witness (nth witness skFORScube u) v =
                   skg ss (ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size skFORSnt)) (size skFORSlp)) 0 (u * t + v)))
             /\ all (fun ls => size ls = t) skFORScube
             /\ size skFORScube <= k)
            (k - size skFORScube).
      + move=> z''.
        wp => /=.
        while (   ad = adz
               /\ (forall (v : int),
                     0 <= v && v < size skFORSet =>
                     nth witness skFORSet v =
                     skg ss (ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size skFORSnt)) (size skFORSlp)) 0 (size skFORScube * t + v)))
               /\ size skFORSet <= t)
            (t - size skFORSet).
        - move=> z'''.
          by wp; skip => />; smt(nth_rcons size_rcons).
        by wp; skip => />; smt(ge2_t nth_rcons size_rcons cats1 all_cat).
      by wp; skip => />; smt(nth_rcons size_rcons ge1_k FTWES.DBLLKTL.valP FTWES.DBLLKTL.insubdK).
    by wp; skip => />; smt(nth_rcons size_rcons).
  wp; do 3! rnd.
  wp; skip => /> ms msin ss ssin ps psin.
  by do 5! (split => [/# | *]) => /#.
call (:   ={qs}(DSSC.Stateless.O_CMA_Default, O_CMA_SPHINCSPLUSTWC_FS)
       /\ DSSC.Stateless.O_CMA_Default.sk{1}
            = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, DSSC.Stateless.O_CMA_Default.sk{1}.`2,
               DSSC.Stateless.O_CMA_Default.sk{1}.`3)
       /\ O_CMA_SPHINCSPLUSTWC_FS.sk{2}
            = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2,
               O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3, DSSC.Stateless.O_CMA_Default.sk{1}.`3)
       /\ (forall (i j u v : int),
             0 <= i && i < nr_trees 0 =>
             0 <= j && j < l' =>
             0 <= u && u < k =>
             0 <= v && v < t =>
             nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2 i) j)) u) v =
             skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
               (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
       /\ (forall (i j u v : int),
            0 <= i && i < d =>
            0 <= j && j < nr_trees i =>
            0 <= u && u < l' =>
            0 <= v && v < len =>
            nth witness (DBLL.val (nth witness (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3 i) j) u)) v =
            skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
              (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))).
+ by apply Eqv_OsignC10_Default_FS.
seq 4 2 : (={leaves} /\ ps0{1} = ps{1} /\ ad0{1} = ad{1} /\ #pre).
+ wp; sp 3 1.
  exists* ss{1}, ps{1}, ad{1}, skWOTStd{2}, ps{2}, ad{2}.
  elim* => ssv psv adv skWv ps2v ad2v.
  call{1} (leaves_sspsad_cf ssv psv (set_ltidx adv (d - 1) 0)).
  call{2} (leaves_cube_cf (nth witness (nth witness skWv (d - 1)) 0) ps2v (set_ltidx ad2v (d - 1) 0)).
  skip; move=> &1 &2.
  move=> hpre.
  split; 1: smt().
  move=> r2.
  move=> r1 cf2.
  split; 1: smt().
  move=> r0.
  move=> res0 cf1.
  split; 2: by smt().
  rewrite cf1 cf2.
  have -> : ps2v = psv by smt().
  have -> : ad2v = adv by smt().
  have -> : adv = adz by smt().
  apply eq_in_mkseq => u rng_u /=.
  do 3! congr.
  apply eq_in_mkseq => v rng_v /=.
  have h1 : 0 <= (d - 1) && (d - 1) < d by smt(ge1_d).
  have h2 : 0 <= 0 && 0 < nr_trees (d - 1).
  + have -> : nr_trees (d - 1) = 2 ^ 0 by (rewrite /nr_trees; smt()).
    by rewrite expr0; smt().
  have hwc : (forall (i j u v : int), 0 <= i && i < d => 0 <= j && j < nr_trees i =>
               0 <= u && u < l' => 0 <= v && v < len =>
               nth witness (DBLL.val (nth witness (nth witness (nth witness skWv i) j) u)) v
               = skg ssv (psv, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)) by smt().
  by rewrite (hwc (d - 1) 0 u v h1 h2 rng_u rng_v).
inline{1} DSSC.Stateless.O_CMA_Default(SPHINCS_PLUS_C10).init.
inline{2} O_CMA_SPHINCSPLUSTWC_FS.init.
wp; skip => &1 &2.
move=> hpre.
split; 1: smt().
move=> *; smt().
qed.

(* The hop-1 Pr equality, derived from the byequiv (MM45's hop-1 feeds the
   capstone's hop1 ledger entry over the free real p_prfprf). *)
lemma Pr_EUFCMA_C10_FSPRFPRFC (F <: Adv_EUFCMA_C{-DSSC.Stateless.O_CMA_Default, -O_CMA_SPHINCSPLUSTWC_FS}) &m :
  Pr[EUFCMA_C10(F).main() @ &m : res]
  = Pr[EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF(F).main() @ &m : res].
proof.
by byequiv (Eqv_EUFCMA_C10_FSPRFPRFC F).
qed.

(* ==========================================================================
   SECTION 10 -- HOP-2: FS_PRFPRF -> FS_NPRFPRF VIA SKG-PRF (scheme-level).

   +C analog of MM45's EqAdv_EUF_CMA_SPHINCSPLUSTWFS_PRFPRF_NPRFPRF_SKGPRF
   (SPHINCS_PLUS.ec:2668-3049) and its reduction R_SKGPRF_EUFCMA
   (SPHINCS_PLUS.ec:1063-1211).

   KEY +C SIMPLIFICATION (auditor-confirmed):  the PRF surface is confined to
   keygen -- the FS oracle O_CMA_SPHINCSPLUSTWC_FS never reads ss/ms, only the
   cubes + ps (Section 5, deltas 1-3).  So the reduction needs NO private
   O_CMA/qs module state (MM45 :1064-1108):  it inits the SHARED FS oracle
   with the built cubes and hands it to A, and the adversary-call invariant
   collapses to ={glob O_CMA_SPHINCSPLUSTWC_FS} with a `sim` oracle case
   (MM45 needed a cross-module sk-tuple invariant + conseq, :2738-2742).

   Also +C-specific:  both FS keygens are CUBE-based end-to-end (Sections
   3-4), so the top-tree leaves call on both sides is the SAME
   FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad (MM45 needed `sim : (={leaves})`
   to bridge seed-vs-cube there, :2743-2745);  every post-cube fact here is
   relational.
   ========================================================================== *)

(* The reduction (MM45 R_SKGPRF_EUFCMA, SPHINCS_PLUS.ec:1063-1211), +C-
   substituted:  draws ms (throwaway, sk-shape parity), ps, ad;  builds the
   FORS + WOTS cubes by querying O at EXACTLY the two skg address families
   (FORS trhftype, WOTS chtype chains);  computes the root with the same
   leaves/val_bt_trh tail as keygen_prf_c;  inits O_CMA_SPHINCSPLUSTWC_FS with
   the built cubes;  runs A(<that oracle>).forge((root, ps));  evaluates the
   +C verify_c + freshness;  returns the win bit. *)
module (R_SKGPRF_EUFCMA_C (A : Adv_EUFCMA_C) : SKG_PRF.Adv_PRF) (O : SKG_PRF.Oracle_PRF) = {
  proc distinguish() : bool = {
    var ad : adrs;
    var ms : mseed;
    var ps : pseed;
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORScube : dgstblock list list;
    var skFORSlp : FTWES.skFORS list;
    var skFORSnt : FTWES.skFORS list list;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var root : dgstblock;
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * FTWES.skFORS list list * skWOTS list list list * pseed;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTWC;
    var is_valid, is_fresh : bool;

    ad <- adz;

    ms <$ dmseed;
    ps <$ dpseed;

    (* FORS cube, queried at the trhftype skg addresses (keygen_prf_c's family,
       Section 3 / MM45 :1137-1159). *)
    skFORSnt <- [];
    while (size skFORSnt < nr_trees 0) {
      skFORSlp <- [];
      while (size skFORSlp < l') {
        skFORScube <- [];
        while (size skFORScube < k) {
          skFORSet <- [];
          while (size skFORSet < t) {
            skFORS_ele <@ O.query(ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSlp)) 0 (size skFORScube * t + size skFORSet));
            skFORSet <- rcons skFORSet skFORS_ele;
          }
          skFORScube <- rcons skFORScube skFORSet;
        }
        skFORSlp <- rcons skFORSlp (FTWES.DBLLKTL.insubd skFORScube);
      }
      skFORSnt <- rcons skFORSnt skFORSlp;
    }

    (* WOTS cube, queried at the chtype chain skg addresses (keygen_prf_c's
       family, Section 3 / MM45 :1161-1183). *)
    skWOTStd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        while (size skWOTSlp < l') {
          skWOTS <- [];
          while (size skWOTS < len) {
            skWOTS_ele <@ O.query(ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) (size skWOTS)) 0);
            skWOTS <- rcons skWOTS skWOTS_ele;
          }
          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
    }

    (* Top-tree leaves + root:  same tail as keygen_prf_c (:1189-1198). *)
    skWOTSlp <- nth witness (nth witness skWOTStd (d - 1)) 0;
    leaves <@ FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);
    root <- val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);

    pk <- (root, ps);
    sk <- (ms, skFORSnt, skWOTStd, ps);

    O_CMA_SPHINCSPLUSTWC_FS.init(sk);

    (m', sig') <@ A(O_CMA_SPHINCSPLUSTWC_FS).forge(pk);

    is_valid <@ SPHINCS_PLUS_C10_FS.verify_c(pk, m', sig');
    is_fresh <@ O_CMA_SPHINCSPLUSTWC_FS.fresh(m');

    return is_valid /\ is_fresh;
  }
}.

(* b = false leg:  O.query = skg k, coupled ss{1} = k{2} (MM45 :2676-2745). *)
lemma EqPr_SKGPRF_C_false (A <: Adv_EUFCMA_C{-SKG_PRF.O_PRF_Default, -O_CMA_SPHINCSPLUSTWC_FS}) &m :
  Pr[EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF(A).main() @ &m : res]
  = Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(A), SKG_PRF.O_PRF_Default).main(false) @ &m : res].
proof.
byequiv => //.
proc.
inline{2} 2.
seq 3 15 : (={pk, m', sig'} /\ ={glob O_CMA_SPHINCSPLUSTWC_FS}).
inline{1} 1.
inline{2} 1.
seq 8 11 : (   ={glob A, ad}
            /\ ! SKG_PRF.O_PRF_Default.b{2}
            /\ ss{1} = SKG_PRF.O_PRF_Default.k{2}
            /\ ms{1} = ms{2} /\ ps{1} = ps{2}
            /\ ={skFORSnt, skWOTStd}).
+ while (   ={skWOTStd}
         /\ ! SKG_PRF.O_PRF_Default.b{2}
         /\ ss{1} = SKG_PRF.O_PRF_Default.k{2}
         /\ size skWOTStd{1} <= d
         /\ #post).
  - wp => /=.
    while (   ={skWOTSnt}
           /\ size skWOTSnt{1} <= nr_trees (size skWOTStd{1})
           /\ #pre).
    * wp => /=.
      while (   ={skWOTSlp}
             /\ size skWOTSlp{1} <= l'
             /\ #pre).
      + wp => /=.
        while (   ={skWOTS}
               /\ size skWOTS{1} <= len
               /\ #pre).
        - inline{2} 1.
          rcondf{2} 2; 1: by auto.
          by wp; skip => />; smt(size_rcons).
        by wp; skip => />; smt(ge2_len size_rcons).
      by wp; skip => />; smt(ge2_lp size_rcons).
    by wp; skip => />; smt(size_rcons IntOrder.expr_ge0).
  wp => /=.
  while (   ={skFORSnt}
         /\ ! SKG_PRF.O_PRF_Default.b{2}
         /\ ss{1} = SKG_PRF.O_PRF_Default.k{2}
         /\ size skFORSnt{1} <= nr_trees 0
         /\ #post).
  - wp => /=.
    while (   ={skFORSlp}
           /\ size skFORSlp{1} <= l'
           /\ #pre).
    * wp => /=.
      while (   ={skFORScube}
             /\ size skFORScube{1} <= k
             /\ #pre).
      + wp => /=.
        while (   ={skFORSet}
               /\ size skFORSet{1} <= t
               /\ #pre).
        - inline{2} 1.
          rcondf{2} 2; 1: by auto.
          by wp; skip => />; smt(size_rcons).
        by wp; skip => />; smt(ge2_t size_rcons).
      by wp; skip => />; smt(ge1_k size_rcons).
    by wp; skip => />; smt(size_rcons IntOrder.expr_ge0).
  wp => /=.
  swap{2} [3..3] 3.
  do 3! rnd.
  by wp; skip => /> *; split;
    [by rewrite /nr_trees; apply IntOrder.expr_ge0
    |by apply (IntOrder.ler_trans 1) => //; exact ge1_d].
call (: ={glob O_CMA_SPHINCSPLUSTWC_FS}).
+ by sim.
call (: ={arg} ==> ={res, glob O_CMA_SPHINCSPLUSTWC_FS}).
+ by sim.
wp.
call (: ={arg} ==> ={res}); 1: by sim.
wp; skip => />; smt().
wp.
call (: ={arg, glob O_CMA_SPHINCSPLUSTWC_FS} ==> ={res, glob O_CMA_SPHINCSPLUSTWC_FS}).
+ by sim.
call (: ={arg} ==> ={res}); 1: by sim.
wp; skip => />; smt().
qed.

(* Arithmetic helper for the FORS-family freshness arithmetic in the true leg
   (MM45's inline `(: size skFORS{m0} = ...) mulzDl -addrA ler_lt_add` chain,
   SPHINCS_PLUS.ec:3013-3016, lifted to a memory-free universal). *)
lemma skgprf_mul_lt : forall (u0 sc0 sf0 t0 v0 : int),
  0 <= u0 => u0 < sc0 => 0 <= v0 => v0 < t0 => 0 <= sf0 =>
  u0 * t0 + v0 < sc0 * t0 + sf0.
proof.
move=> u0 sc0 sf0 t0 v0 ge0u ltu ge0v ltv ge0sf.
rewrite (: sc0 = sc0 - 1 + 1) 1:// mulzDl /= -addrA.
rewrite ler_lt_add 1:ler_pmul 4://; 1..3: smt().
by rewrite -addr0 ltr_le_add; smt().
qed.

(* b = true leg:  lazy RF;  every queried address FRESH via the two-family
   domain invariant (MM45's mdom, :2762-2976), so lazy = eager uniform cube
   (MM45 :2746-3048). *)
lemma EqPr_SKGPRF_C_true (A <: Adv_EUFCMA_C{-SKG_PRF.O_PRF_Default, -O_CMA_SPHINCSPLUSTWC_FS}) &m :
  Pr[EUF_CMA_SPHINCSPLUSTWC_FS_NPRFPRF(A).main() @ &m : res]
  = Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(A), SKG_PRF.O_PRF_Default).main(true) @ &m : res].
proof.
byequiv => //.
proc.
inline{2} 2.
seq 3 15 : (={pk, m', sig'} /\ ={glob O_CMA_SPHINCSPLUSTWC_FS}).
inline{1} 1.
inline{2} 1.
seq 8 11 : (   ={glob A, ad}
            /\ ad{2} = adz
            /\ SKG_PRF.O_PRF_Default.b{2}
            /\ ss{1} = SKG_PRF.O_PRF_Default.k{2}
            /\ ms{1} = ms{2} /\ ps{1} = ps{2}
            /\ ={skFORSnt, skWOTStd}).
+ while (   SKG_PRF.O_PRF_Default.b{2}
         /\ (forall (psad : pseed * adrs),
               psad \in SKG_PRF.O_PRF_Default.m{2}
               <=>
               ((exists (i j u v : int), 
                   0 <= i < nr_trees 0 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                   psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                \/ 
                (exists (i j u v : int),
                   0 <= i < size skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\ 
                   psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))))
         /\ size skWOTStd{1} <= d
         /\ #post).
  - wp => /=.
    while (   ={skWOTSnt}
           /\ ad{2} = adz
           /\ SKG_PRF.O_PRF_Default.b{2}
           /\ ={skWOTStd}
           /\ (forall (psad : pseed * adrs),
                 psad \in SKG_PRF.O_PRF_Default.m{2}
                 <=>
                 ((exists (i j u v : int), 
                     0 <= i < nr_trees 0 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                     psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                  \/ 
                  (exists (i j u v : int),
                     0 <= i < size skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\ 
                     psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))
                  \/ (exists (j u v : int),
                      0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\ 0 <= v < len /\ 
                       psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) j) chtype) u) v) 0))))
           /\ size skWOTStd{1} < d
           /\ size skWOTSnt{1} <= nr_trees (size skWOTStd{1})).
    * wp => /=.
      while (   ={skWOTSnt, skWOTSlp}
             /\ ad{2} = adz
             /\ SKG_PRF.O_PRF_Default.b{2}
             /\ ={skWOTStd}
             /\ (forall (psad : pseed * adrs),
                   psad \in SKG_PRF.O_PRF_Default.m{2}
                   <=>
                   ((exists (i j u v : int), 
                       0 <= i < nr_trees 0 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                       psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                    \/ 
                    (exists (i j u v : int),
                       0 <= i < size skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\ 
                       psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))
                    \/ (exists (j u v : int),
                        0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\ 0 <= v < len /\ 
                         psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) j) chtype) u) v) 0))
                    \/ (exists (u v : int),
                        0 <= u < size skWOTSlp{2} /\ 0 <= v < len /\ 
                         psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) (size skWOTSnt{2})) chtype) u) v) 0))))
             /\ size skWOTStd{1} < d
             /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
             /\ size skWOTSlp{1} <= l').
      + wp => /=.
        while (   ={skWOTSnt, skWOTSlp, skWOTS}
               /\ ad{2} = adz
               /\ SKG_PRF.O_PRF_Default.b{2}
               /\ ={skWOTStd}
               /\ (forall (psad : pseed * adrs),
                     psad \in SKG_PRF.O_PRF_Default.m{2}
                     <=>
                     ((exists (i j u v : int), 
                         0 <= i < nr_trees 0 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                         psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                      \/ 
                      (exists (i j u v : int),
                         0 <= i < size skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\ 
                         psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))
                      \/ (exists (j u v : int),
                          0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\ 0 <= v < len /\ 
                           psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) j) chtype) u) v) 0))
                      \/ (exists (u v : int),
                          0 <= u < size skWOTSlp{2} /\ 0 <= v < len /\ 
                           psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) (size skWOTSnt{2})) chtype) u) v) 0))
                      \/ (exists (v : int),
                          0 <= v < size skWOTS{2} /\ 
                           psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) (size skWOTSnt{2})) chtype) (size skWOTSlp{2})) v) 0))))
               /\ size skWOTStd{1} < d
               /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
               /\ size skWOTSlp{1} < l'
               /\ size skWOTS{1} <= len).
        - inline{2} 1.
          rcondt{2} 2; 1: by auto.
          rcondt{2} 2.
          * auto => /> &2 bt mdom *.
            pose psad := (_, set_hidx _ _).
            move/iffLR /contra: (mdom psad) => -> //=.
            rewrite ?negb_or; split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 3 => @/HA.eq_idx.
              rewrite setalladzch_gettypeidx 1..4:// setalladztrhf_gettypeidx //;
                2: by (have := SPHINCS_PLUS.dist_adrstypes; rewrite /= => -[hc _]; apply/negP => heq; apply: hc; rewrite heq).
              rewrite /valid_tbfidx /nr_nodesf /=; split => [/# | _].
              by rewrite (: k = k - 1 + 1) // mulzDl /= -/t ler_lt_add 1:ler_pmul 4://; smt(ge2_t).
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 5 => @/HA.eq_idx.
              by rewrite ?setalladzch_getlidx 1..8:// /#. 
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 4 => @/HA.eq_idx.
              by rewrite ?setalladzch_gettidx 1..8:// /valid_tidx /#.        
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 2 => @/HA.eq_idx.
              by rewrite ?setalladzch_getkpidx 1..8:// /valid_tidx /#.
            do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
            rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 1 => @/HA.eq_idx.
            by rewrite ?setallchadz_getchidx 1..8:// /valid_tidx /#.
          wp; rnd; wp; skip => /> &2 bt mdom *.
          rewrite -!andbA andbA; split; 2: smt(size_rcons).
          rewrite get_set_sameE oget_some /= => psad.
          split => [/mem_set [| -> /=]|]; 1,2: smt(size_ge0 size_rcons).
          move=> mdomrc; rewrite mem_set /=.
          case (psad \in SKG_PRF.O_PRF_Default.m{2}) => [// | /= ninm].
          move/iffRL /contra: (mdom psad) mdomrc => /(_ ninm) /=.
          rewrite ?negb_or => [#] -> -> -> -> /=; rewrite negb_exists => /= ninskw /=.
          move=> -[v]; rewrite size_rcons => -[rng_v psadval /=].
          case (v = size skWOTS{2}) => [ // | neqszv].
          by move: (ninskw v); rewrite negb_and (: 0 <= v && v < size skWOTS{2}) /#.
        wp; skip => /> &2 *.
        split => [* | psdbmap skw ? _ psdbmapdef ?]; 1: smt(ge2_len).
        split => [psad |]; 2: smt(size_rcons).
        by split => [/psdbmapdef | ]; smt(size_rcons size_ge0).
      wp; skip => /> &2 *.
      split => [* | psdbmap skw ? _ psdbmapdef ?]; 1: smt(ge2_lp).
      split => [psad |]; 2: smt(size_rcons).
      by split => [/psdbmapdef | ]; smt(size_rcons size_ge0).
    wp; skip => /> &2 bT mdef _ ltd_szsktd.
    split => [ * | psdbmap skw ? _ psdbmapdef ?]; 1: rewrite expr_ge0 1:// 1:/=.
    * by move => psad; split => [/mdef |] /#.
    split => [psad |]; 2: smt(size_rcons).
    by split => [/psdbmapdef | ]; smt(size_rcons size_ge0).
  wp => /=.
  while (   SKG_PRF.O_PRF_Default.b{2}
         /\ ad{2} = adz
         /\ ={skFORSnt}
         /\ (forall (psad : pseed * adrs),
               psad \in SKG_PRF.O_PRF_Default.m{2}
               <=>
               (exists (i j u v : int), 
                   0 <= i < size skFORSnt{2} /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                   psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v))))
         /\ size skFORSnt{1} <= nr_trees 0).
  - wp => /=.
    while (   ={skFORSlp}
           /\ ad{2} = adz
           /\ SKG_PRF.O_PRF_Default.b{2}
           /\ ={skFORSnt}
           /\ (forall (psad : pseed * adrs),
                 psad \in SKG_PRF.O_PRF_Default.m{2}
                 <=>
                 ((exists (i j u v : int), 
                     0 <= i < size skFORSnt{2} /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                     psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                  \/
                  (exists (j u v : int), 
                     0 <= j < size skFORSlp{2} /\ 0 <= u < k /\ 0 <= v < t /\ 
                     psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size skFORSnt{2})) j) 0 (u * t + v)))))
           /\ size skFORSnt{1} < nr_trees 0
           /\ size skFORSlp{1} <= l').
    * wp => /=.
      while (   ={skFORSlp, skFORScube}
             /\ ad{2} = adz 
             /\ SKG_PRF.O_PRF_Default.b{2}
             /\ ={skFORSnt}
             /\ (forall (psad : pseed * adrs),
                   psad \in SKG_PRF.O_PRF_Default.m{2}
                   <=>
                   ((exists (i j u v : int), 
                       0 <= i < size skFORSnt{2} /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                       psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                    \/
                    (exists (j u v : int), 
                       0 <= j < size skFORSlp{2} /\ 0 <= u < k /\ 0 <= v < t /\ 
                       psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size skFORSnt{2})) j) 0 (u * t + v)))
                    \/
                    (exists (u v : int), 
                       0 <= u < size skFORScube{2} /\ 0 <= v < t /\ 
                       psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size skFORSnt{2})) (size skFORSlp{2})) 0 (u * t + v)))))
             /\ size skFORSnt{1} < nr_trees 0
             /\ size skFORSlp{1} < l'
             /\ size skFORScube{1} <= k).
      + wp => /=.
        while (   ={skFORSlp, skFORScube, skFORSet} 
               /\ ad{2} = adz 
               /\ SKG_PRF.O_PRF_Default.b{2}
               /\ ={skFORSnt}
               /\ (forall (psad : pseed * adrs),
                     psad \in SKG_PRF.O_PRF_Default.m{2}
                     <=>
                     ((exists (i j u v : int), 
                         0 <= i < size skFORSnt{2} /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                         psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                      \/
                      (exists (j u v : int), 
                         0 <= j < size skFORSlp{2} /\ 0 <= u < k /\ 0 <= v < t /\ 
                         psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size skFORSnt{2})) j) 0 (u * t + v)))
                      \/
                      (exists (u v : int), 
                         0 <= u < size skFORScube{2} /\ 0 <= v < t /\ 
                         psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size skFORSnt{2})) (size skFORSlp{2})) 0 (u * t + v)))
                      \/ 
                      (exists (v : int),
                         0 <= v < size skFORSet{2} /\ 
                          psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size skFORSnt{2})) (size skFORSlp{2})) 0 ((size skFORScube{2}) * t + v)))))
               /\ size skFORSnt{1} < nr_trees 0
               /\ size skFORSlp{1} < l'
               /\ size skFORScube{1} < k
               /\ size skFORSet{1} <= t).
        - inline{2} 1.
          rcondt{2} 2; 1: by auto.
          rcondt{2} 2.
          * auto => /> &2 bt mdom *.
            pose psad := (_, set_thtbidx _ _ _).
            move/iffLR /contra: (mdom psad) => -> //=.
            rewrite ?negb_or; split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 4 => @/HA.eq_idx.
              rewrite ?setalladztrhf_gettidx 1,2,5:// 2,4:/#.
              - rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
                rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
                by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
              rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
              rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
              by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 2 => @/HA.eq_idx.
              rewrite ?setalladztrhf_getkpidx 1,2,4:// 2,4:/#.
              - rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
                rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
                by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
              rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
              rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
              by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 0 => @/HA.eq_idx.              
              rewrite ?setalladztrhf_getbidx 1,2,4,5://.
              - rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
                rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
                by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
              - rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
                rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
                by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
              rewrite neq_ltz; right.
              by smt(skgprf_mul_lt size_ge0 ge2_t).
            do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
            rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 0 => @/HA.eq_idx.      
            rewrite ?setalladztrhf_getbidx 1,2,4,5://.
            + rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
              rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
              by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
            + rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
              rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
              by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
            by rewrite neq_ltz; right; rewrite ler_lt_add 1:// /#.
          wp; rnd; wp; skip => /> *.
          by rewrite get_set_sameE oget_some /=; smt(size_rcons size_ge0 mem_set).
        wp; skip => /> *. 
        split => *; 1: smt(ge2_t).
        by split; smt(size_rcons size_ge0). 
      by wp; skip => />; smt(size_rcons size_ge0 ge1_k).
    by wp; skip => />; smt(size_rcons size_ge0 ge2_lp).
  wp => /=.
  swap{2} [3..3] 3.
  do 3! rnd.
  wp; skip => /> *.
  split => [| skf psam]; 1: split => [ps |]; 2: by rewrite IntOrder.expr_ge0.
  - by rewrite mem_empty /= => i j u v /#.
  by move/lezNgt => gent0_szskf _ psamdef lent0_szskf; split; smt(ge1_d).
call (: ={glob O_CMA_SPHINCSPLUSTWC_FS}).
+ by sim.
call (: ={arg} ==> ={res, glob O_CMA_SPHINCSPLUSTWC_FS}).
+ by sim.
wp.
call (: ={arg} ==> ={res}); 1: by sim.
wp; skip => />; smt().
wp.
call (: ={arg, glob O_CMA_SPHINCSPLUSTWC_FS} ==> ={res, glob O_CMA_SPHINCSPLUSTWC_FS}).
+ by sim.
call (: ={arg} ==> ={res}); 1: by sim.
wp; skip => />; smt().
qed.

(* The composed hop (pure arithmetic on the two legs;  MM45 folds this into
   the capstone at :4300-4330). *)
lemma SKGPRF_C_hop (A <: Adv_EUFCMA_C{-SKG_PRF.O_PRF_Default, -O_CMA_SPHINCSPLUSTWC_FS}) &m :
  Pr[EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF(A).main() @ &m : res]
  <=   Pr[EUF_CMA_SPHINCSPLUSTWC_FS_NPRFPRF(A).main() @ &m : res]
     + `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(A), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
         - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(A), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |.
proof.
have hf := EqPr_SKGPRF_C_false A &m.
have ht := EqPr_SKGPRF_C_true A &m.
smt().
qed.

(* ==========================================================================
   hop-3 (MKG-PRF, NPRFPRF -> NPRFNPRF) -- RESOLUTION: FINDING, NOT A PAID HOP.
   ==========================================================================

   The +C analog of MM45 EqAdv_EUF_CMA_SPHINCSPLUSTWFS_NPRFPRF_NPRFNPRF_MKGPRF
   (SPHINCS_PLUS.ec:3055-3128) does NOT port as a paid message-key PRF hop at
   this (scheme / FX) level.  Determined 2026-07-24 by source reading + two
   independent external reviews (GPT-5.6, Kimi K3) + advisor; all four converge
   on FINDING (Kimi additionally would bank the collapse as a proved identity;
   GPT-5.6 + advisor reject a byte-copy game as reflexivity theatre -- this block
   records the resolution WITHOUT such a game, per the latter two).

   WHY THE IN-CHAIN HOP IS THE IDENTITY.
     C10 models the message key R as a fresh, NON-memoized, +C-conditioned draw
     `mk <$ dcond dmkey (good_fors m)` on EVERY game of this chain:
       - the modelled real scheme   SPHINCS_PLUS_C10.sign          (:193)
       - the FS CMA oracle          O_CMA_SPHINCSPLUSTWC_FS.sign   (:460)
                                    (shared by PRFPRF and NPRFPRF)
       - the downstream V game      V_C.O_CMA_C.sign
                                    (rtop_c_soundness_wip.ec:347)
     `mkg` is NEVER APPLIED anywhere in this chain (grep: it occurs only inside
     "NOT mkg" comments).  A FAITHFUL NPRFNPRF -- message key from the idealised
     random source, feeding V_C -- is therefore definitionally EQUAL to NPRFPRF
     (same keygen_nprf_c, same oracle, same verify_c):
         Pr[EUF_CMA_..._NPRFPRF(A)] = Pr[<faithful NPRFNPRF>(A)]   (by sim).
     The concrete hop-3 is that EQUALITY, i.e. the +C MKG hop COLLAPSES.  It is
     deliberately NOT stated as a `<= ... + |MKG_PRF|` triangle: there is no
     keyed mkg to reduce, so no reduction module R_MKGPRF_EUFCMA_C and no
     EqPr_MKGPRF_C_false/true exist.  A hop with nothing to perturb (the required
     non-vacuity perturbation on MKG freshness is INAPPLICABLE by construction)
     is not a hop.

   WHY THE MM45 (memoized) SHAPE IS NOT MERELY UNFAITHFUL BUT FALSE AT +C.
     C10's R is randomized per signature (fresh opt_rand every call; production
     FORS_C10.ec:44-70, regression positive_opt_rand_changes_sig_bytes).  Two
     sign(m) queries give independent R in the fresh model but EQUAL R in a
     memoized-RF model, so the two games are transcript-distinguishable -- a
     memoized NPRFNPRF is NOT `<= NPRFPRF + negl`; the MM45-shaped inequality is
     the wrong object, not a conservative one.  MM45's MKG_PRF clone
     (SPHINCS_PLUS.ec:409-423, in_t = msg, one query per message) also cannot
     express a per-signature grind over fresh randomness.

   WHERE THE GENUINE mkg TERM LIVES (it is NOT zero).
     Production derives each grind candidate by a KEYED hash of sk_seed with
     opt_rand and a nonce (PQSigner sphincs-c10/src/fors.rs nonce loop), so
     idealising that keyed derivation to the uniform-conditioned `dcond` draw IS
     a real random-oracle step -- the same idealisation MM45 makes for the mco /
     ITSR key without a PRF hop (FORS_C10.ec:52-54).  That step sits at the
     MODEL-DEFINITION / pre-hop-1 boundary (a keyed salted-grinder LHS -> the
     current dcond-modelled EUFCMA_C10), NOT between NPRFPRF and NPRFNPRF.  A
     genuine boundary hop would need a NEW primitive (in_t carrying salt+nonce,
     multiple queries per signature) plus finite-failure / opt_rand-collision
     accounting; it does not fit the message-only MKG_PRF clone.

   ACCOUNTING HAZARD FOR THE CAPSTONE (H1 -- must fix WITH this resolution).
     sphincs_c10_capstone_concrete_wip.ec:515 carries
       `hop3 : p_nprfprf <= p_nprfnprf + mkg_adv`  (admit; mkg_adv a FREE real).
     Once the in-chain step is recognised as the identity (p_nprfprf =
     p_nprfnprf), mkg_adv becomes a PHANTOM summand: sound as an upper bound but
     silently zeroable by a consumer, and double-paying if kept alongside the
     already-idealised dcond LHS.  Honest fix: drop mkg_adv from the +C FX
     PRF-term sum and cite the model-definition RO-idealisation ledger
     (sphincs_c10_scheme_wip.ec:52-67, FORS_C10.ec:52-54), OR relocate it to an
     explicit pre-hop-1 boundary hop.  Do NOT leave it as an in-chain MKG-PRF
     summand.

   SCOPE: this resolves hop-3's IN-CHAIN status only.  It does NOT discharge the
   mkg RO-idealisation and does NOT claim SPHINCS+C proven (hop-4/5/6 + ITSRC10
   + the pre-hop-1 boundary all remain open).
   ========================================================================== *)

(* ==========================================================================
   hop-4 (FS-NPRFPRF -> V_C) -- THE VALIDITY-INLINING FX HOP.
   ==========================================================================

   The +C analog of MM45 Eqv_EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V
   (SPHINCS_PLUS.ec:2572) + the mu_split (:4327).  Connects the terminal FS
   game EUF_CMA_SPHINCSPLUSTWC_FS_NPRFPRF (Section 6, ~:519 -- the terminal FX
   game per the hop-3 IDENTITY finding above) to the VALIDITY-INLINED game V_C,
   then splits on the boolean `valid_MFORSC10`.

   V_C = module EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.  SINGLE-SOURCED, inherited from
   RtopCSoundness via `require import` (the earlier inline byte-copy was deleted
   2026-07-24 -- see the delete-note immediately below at :2876).  It is the STABLE
   game that hop-5 (LeqPr_VT_C) and hop-6 (RtopCSoundness.LeqPr_VF_C) both consume;
   the split probabilities p_vt = Pr[V_C : res /\ valid_MFORSC10] and
   p_vf = Pr[V_C : res /\ !valid_MFORSC10] MUST be exactly those two, and single-
   sourcing makes that a MODULE IDENTITY (the same V_C both hops name), machine-
   checked, not byte-equality.  Edit the game ONLY in RtopCSoundness.

   WHY hop-4 is a genuine (not-vacuous) inlining, NOT a weakened post.
   The byequiv Eqv_NPRFPRF_V_C proves ==> ={res} (FULL two-sided equality, not
   res{1} => res{2}); V_C only INLINES the +C verify (verify_c = SPHINCS_PLUS_C10.
   verify, whose return was written at :244 to MIRROR V_C's is_valid) and records
   the spectator flag `valid_MFORSC10` (a module var absent from `res`).  The two
   games share: the SAME cube-based NPRF keygen (FORS cube + FL_SL_XMSS_MT_C_ES_NPRF
   .keygen, byte-identical draws), the SAME +C oracle sign body (dcond mk draw,
   FL_FORS_ES_NPRF.sign / gen_pkFORS / FL_SL_XMSS_MT_C_ES_NPRF.sign), and the SAME
   fresh check.  keygen_nprf_c's dead `ms`/`ss` draws (never read by the NPRF
   oracle -- mk is a fresh dcond draw, cubes are ddgstblock-sampled) are dropped
   one-sided (dmseed_ll / dsseed_ll).  The mu_split identity is EXACT (Pr on a
   boolean).  Structural same-proc `sim` helpers below couple the shared FL_*
   procedure calls (the FORS-cube module var vs local naming mismatch defeats a
   whole-program `sim`, so the cubes are coupled by explicit rnd-aligned whiles).
   ========================================================================== *)
(* EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V (the V_C game) -- SINGLE-SOURCED, inherited
   from RtopCSoundness (deleted here 2026-07-24; the deleted 131-line module was
   diff-confirmed BYTE-IDENTICAL to RtopCSoundness's, so Eqv_NPRFPRF_V_C /
   hop4_musplit below now byequiv against the SAME module RtopCSoundness.LeqPr_VF_C
   consumes -- this is the machine-checked p_vf seam).  The explanatory header
   above still describes that shared game. *)

(* ---- same-proc structural equivs (all pure, proc; sim) ---- *)
equiv leaves_eq :
  FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad ~ FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad :
  ={skWOTSl, ps, ad} ==> ={res}.
proof. proc. sim. qed.

equiv forssign_eq :
  FTWES.FL_FORS_ES_NPRF.sign ~ FTWES.FL_FORS_ES_NPRF.sign : ={arg} ==> ={res}.
proof. proc. sim. qed.

equiv genpkfors_eq :
  FTWES.FL_FORS_ES_NPRF.gen_pkFORS ~ FTWES.FL_FORS_ES_NPRF.gen_pkFORS : ={arg} ==> ={res}.
proof. proc. sim. qed.

equiv htsign_eq :
  FL_SL_XMSS_MT_C_ES_NPRF.sign ~ FL_SL_XMSS_MT_C_ES_NPRF.sign : ={arg} ==> ={res}.
proof. proc. sim. qed.

equiv forspk_from_sig_eq :
  FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW ~ FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW : ={arg} ==> ={res}.
proof. proc. sim. qed.

equiv rootfromsigc_eq :
  FL_SL_XMSS_MT_C_ES.root_from_sigC ~ FL_SL_XMSS_MT_C_ES.root_from_sigC : ={arg} ==> ={res}.
proof. proc. sim. qed.

lemma Eqv_NPRFPRF_V_C (A <: Adv_EUFCMA_C{-O_CMA_SPHINCSPLUSTWC_FS, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V}) :
  equiv[ EUF_CMA_SPHINCSPLUSTWC_FS_NPRFPRF(A).main ~ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V(A).main :
         ={glob A} ==> ={res} ].
proof.
proc.
inline{1} SPHINCS_PLUS_C10_FS.keygen_nprf_c.
inline{2} FL_SL_XMSS_MT_C_ES_NPRF.keygen.
(* (a) prefix: drop dead ms/ss, couple ps *)
seq 4 2 : (   ={glob A}
           /\ ps{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2}
           /\ ad{1} = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{2} = adz).
+ sp 1 1; rnd; rnd{1}; rnd{1}; skip => />; smt(dmseed_ll dsseed_ll).
(* (b) FORS cube: skFORSnt is module var on {2}, bare local on {1} -> explicit whiles *)
seq 2 2 : (   ={glob A}
           /\ ps{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2}
           /\ ad{1} = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{2} = adz
           /\ skFORSnt{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{2}).
+ sp 1 1.
  while (skFORSnt{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{2}).
  + wp.
    while (   skFORSlp{1} = skFORSlp{2}
           /\ skFORSnt{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{2}).
    + wp.
      while (   skFORScube{1} = skFORScube{2}
             /\ skFORSlp{1} = skFORSlp{2}
             /\ skFORSnt{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{2}).
      + wp.
        while (   skFORSet{1} = skFORSet{2}
               /\ skFORScube{1} = skFORScube{2}
               /\ skFORSlp{1} = skFORSlp{2}
               /\ skFORSnt{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{2}).
        + wp; rnd; skip => />.
        wp; skip => />; smt(size_rcons).
      wp; skip => />; smt(size_rcons).
    wp; skip => />; smt(size_rcons).
  skip => />; smt(size_rcons).
(* (c) WOTS cube: bare local on both sides, sync via ={...} *)
sp 0 2.
seq 2 2 : (   ={glob A}
           /\ ps{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2}
           /\ ps{2} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2}
           /\ ad{1} = adz /\ ad{2} = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{2} = adz
           /\ skFORSnt{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{2}
           /\ ={skWOTStd}).
+ sp 1 1.
  while (={skWOTStd}).
  + wp.
    while (={skWOTSnt, skWOTStd}).
    + wp.
      while (={skWOTSlp, skWOTSnt, skWOTStd}).
      + wp.
        while (={skWOTS, skWOTSlp, skWOTSnt, skWOTStd}).
        + wp; rnd; skip => />.
        wp; skip => />; smt(size_rcons).
      wp; skip => />; smt(size_rcons).
    wp; skip => />; smt(size_rcons).
  skip => />; smt(size_rcons).
(* (d) leaves + root *)
seq 3 3 : (   ={glob A, skWOTStd, root}
           /\ ps{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2}
           /\ ps{2} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2}
           /\ ad{1} = adz /\ ad{2} = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{2} = adz
           /\ skFORSnt{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{2}).
+ wp. call leaves_eq. wp; skip => />.
(* (e) plumbing -> PRE_FORGE *)
inline{1} O_CMA_SPHINCSPLUSTWC_FS.init.
seq 6 6 : (   ={glob A}
           /\ pk{1} = (EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.root{2}, EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2})
           /\ O_CMA_SPHINCSPLUSTWC_FS.sk{1}.`2 = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{2}
           /\ O_CMA_SPHINCSPLUSTWC_FS.sk{1}.`3 = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{2}
           /\ O_CMA_SPHINCSPLUSTWC_FS.sk{1}.`4 = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2}
           /\ O_CMA_SPHINCSPLUSTWC_FS.qs{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.qs{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{2} = adz).
+ wp; skip => />.
(* (f) isolate + couple forge via the oracle invariant *)
seq 1 1 : (   ={glob A}
           /\ m'{1} = m'{2} /\ sig'{1} = sig'{2}
           /\ pk{1} = (EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.root{2}, EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2})
           /\ O_CMA_SPHINCSPLUSTWC_FS.qs{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.qs{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{2} = adz).
+ call (:   O_CMA_SPHINCSPLUSTWC_FS.sk{1}.`2 = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{2}
         /\ O_CMA_SPHINCSPLUSTWC_FS.sk{1}.`3 = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{2}
         /\ O_CMA_SPHINCSPLUSTWC_FS.sk{1}.`4 = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2}
         /\ O_CMA_SPHINCSPLUSTWC_FS.qs{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.qs{2}
         /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{2} = adz).
  + proc.
    sp 2 0.
    seq 1 1 : (   O_CMA_SPHINCSPLUSTWC_FS.sk{1}.`2 = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{2}
               /\ O_CMA_SPHINCSPLUSTWC_FS.sk{1}.`3 = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{2}
               /\ O_CMA_SPHINCSPLUSTWC_FS.sk{1}.`4 = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2}
               /\ O_CMA_SPHINCSPLUSTWC_FS.qs{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.qs{2}
               /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{2} = adz
               /\ ={m, mk}
               /\ skFORSnt{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{2}
               /\ skWOTStd{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{2}
               /\ ps{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2}
               /\ ad{1} = adz).
    + rnd; skip => />.
    seq 3 3 : (   O_CMA_SPHINCSPLUSTWC_FS.sk{1}.`2 = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{2}
               /\ O_CMA_SPHINCSPLUSTWC_FS.sk{1}.`3 = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{2}
               /\ O_CMA_SPHINCSPLUSTWC_FS.sk{1}.`4 = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2}
               /\ O_CMA_SPHINCSPLUSTWC_FS.qs{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.qs{2}
               /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{2} = adz
               /\ ={m, mk, cm, idx, tidx, kpidx, skFORS}
               /\ skWOTStd{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{2}
               /\ ps{1} = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{2}
               /\ ad{1} = adz).
    + wp; skip => />.
    wp. call htsign_eq. wp. call genpkfors_eq. call forssign_eq. wp; skip; smt().
  auto.
(* (g) verify (inline) + fresh: is_valid equal; spectator gen_pkFORS one-sided *)
inline{1} SPHINCS_PLUS_C10_FS.verify_c.
inline{1} O_CMA_SPHINCSPLUSTWC_FS.fresh.
wp.
call rootfromsigc_eq.
wp.
call forspk_from_sig_eq.
call{2} genpkfors_ll.
wp; skip => />.
qed.

(* ---- hop-4 mu_split packaging ---- *)
lemma hop4_musplit (A <: Adv_EUFCMA_C{-O_CMA_SPHINCSPLUSTWC_FS, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V}) &m :
  Pr[EUF_CMA_SPHINCSPLUSTWC_FS_NPRFPRF(A).main() @ &m : res]
  = Pr[EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V(A).main() @ &m : res /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.valid_MFORSC10]
  + Pr[EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V(A).main() @ &m : res /\ ! EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.valid_MFORSC10].
proof.
have ->:
  Pr[EUF_CMA_SPHINCSPLUSTWC_FS_NPRFPRF(A).main() @ &m : res]
  = Pr[EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V(A).main() @ &m : res].
+ by byequiv (Eqv_NPRFPRF_V_C A).
by rewrite Pr[mu_split EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.valid_MFORSC10].
qed.
