(* ==========================================================================
   GprocFORSC10.ec -- the PROCEDURAL FORS+C10 multi-instance EUF-CMA game
   (Gproc), the SOUND reduction target for hop5 (the VT / FORS-forgery branch of
   the SPHINCS+C10 capstone).

   WHY THIS FILE EXISTS (Waves 9-11, docs/verification/...-2026-07.md).
   The ABSTRACT game FORS_C10_Multi.MFORSC10 (cloned as `M` here) CANNOT be the
   hop5 reduction target:
     (D1) its `fverify` is an UNCONSTRAINED op -- `fverify := false` zeroes
          Pr[RHS] keygen-independently (rtop_c_vt_wip.rhs_zero_fverify_false), so
          a bound against it is vacuous;
     (D2) its `mkeygen` is a PURE OP deriving the FORS cube DETERMINISTICALLY from
          ps, but V_C samples the cube  skFORS_ele <$ ddgstblock  ps-INDEPENDENTLY
          (RtopCSoundness.ec:402), so no equality-supported coupling exists.
   The pseed-WRAP escape (RTopCVtMcWrapSeed.ec) reconciles D2 but leaves fverify
   abstract (D1 open) and buries the secret cube in ps (tape-in-ps soundness
   landmine).  The CONVERGED SOUND FIX (advisor + GPT-5.6 + Kimi) is a CONCRETE
   PROCEDURAL game whose

     * keygen is a PROC that SAMPLES the cube  skFORS_ele <$ ddgstblock
       ps-INDEPENDENTLY, byte-mirroring V_C's draw (RtopCSoundness.ec:394-410)  ->
       reconciles D2 BY CONSTRUCTION;
     * verify is CONCRETE -- reconstructed-pkFORS equality
       (FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW = the precomputed pool entry) AND
       predC_fors -- the EXACT V_C `valid_MFORSC10` check  ->  closes D1 (fverify
       is not zeroable);
     * sign is the concrete routed FORS+C sign  (FL_FORS_ES_NPRF.sign),
       fresh CONDITIONED mk  <$ dcond dmkey (good_fors m)  NON-memoized, matching
       V_C.O_CMA_C.sign EXACTLY.

   Structurally mirrors MM45's PROCEDURAL M_FORS_ES_NPRF (FORS_ES.ec:1933 keygen /
   :2055 sign / :1629 pkFORS_from_sigFORSTW / :1839 gen_pkFORS) with the two C10
   substitutions (fresh conditioned mk; predC_fors gate).

   THE BRIDGE-VS-REDERIVE DECISION (task Step 2).  The BRIDGE (prove
   Pr[Gproc EUF] = Pr[MFORSC10 EUF at concrete ops] by byequiv, then instantiate
   the abstract EUFCMA_MFORSC10) is REJECTED, not attempted: the abstract game's
   keygen  (pks,sks) <- mkeygen ps ad  is a DETERMINISTIC op of ps, while Gproc's
   keygen SAMPLES the cube ps-independently.  No concrete op reproduces a sampling
   distribution under the honest `dpseed`; the only "fix" (put the cube in ps) IS
   the tape-in-ps landmine Gproc exists to kill.  So the bridge is self-defeating.
   We RE-DERIVE the ITSRC10 chain over Gproc (Step 2 below), which is tractable:
   each of the three FORS_C10_Multi lemmas is its proof + a `sim` keygen prefix,
   because Gproc runs identical sampling code on both sides of every byequiv and
   the covered/ts coupling is nesting-agnostic.
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder IntDiv.
require import DList DMap FMap.
require import BinaryTrees MerkleTrees.
require import BitEncoding.
import BS2Int BitChunking.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
require import RtopCSoundness.
(* for fors_leaves_op_cube, used by the brick-2b pk characterisations below;
   FxChain precedes this file in closure-c10-split.txt so there is no cycle *)
require import FxChain.
require FORS_C10 FORS_C10_Multi.
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

(* --------------------------------------------------------------------------
   The FIVE concrete g-facts (FORSC10's five g-axioms at the FTWES types),
   needed for the MFORSC10 clone realize clauses.  INLINED verbatim from
   rtop_c_vt_wip.ec:222-260 (= good_clone_probe.ec:66-107).
   -------------------------------------------------------------------------- *)
lemma ftw_size_g (y : FTWES.msgFORSTW * index) : size (FTWES.g y) = k.
proof. by rewrite /FTWES.g /= size_mkseq; smt(ge1_k). qed.

lemma ftw_eqiks_g (x x' : int * int * int) (y : FTWES.msgFORSTW * index) :
  x \in FTWES.g y => x' \in FTWES.g y => x.`1 = x'.`1.
proof. by rewrite /FTWES.g /= => /mkseqP [i [_ ->]] /mkseqP [j [_ ->]] /=. qed.

lemma ftw_neqisvs_g (x x' : int * int * int) (y : FTWES.msgFORSTW * index) :
  x \in FTWES.g y => x' \in FTWES.g y => x <> x' => x.`2 <> x'.`2.
proof. by rewrite /FTWES.g /= => /mkseqP [i [_ ->]] /mkseqP [j [_ ->]] /=; smt(). qed.

lemma ftw_rng_g (y : FTWES.msgFORSTW * index) (x : int * int * int) :
  x \in FTWES.g y => 0 <= x.`3 < t.
proof.
rewrite /FTWES.g /= => /mkseqP [i [rng_i ->]] /=.
split; 1: exact bs2int_ge0.
move => _.
have ha : 0 < a by smt(ge1_a).
have szc : size (nth witness (chunk a (FTWES.BLKAL.val y.`1)) i) = a.
- apply: (in_chunk_size a (FTWES.BLKAL.val y.`1)
                     (nth witness (chunk a (FTWES.BLKAL.val y.`1)) i) ha).
  apply/mem_nth.
  rewrite (size_chunk a _ ha) FTWES.BLKAL.valP.
  smt(ge1_a).
have -> : t = 2 ^ a by rewrite /t.
have hlt := bs2int_le2Xs (rev (nth witness (chunk a (FTWES.BLKAL.val y.`1)) i)).
rewrite size_rev szc in hlt.
exact hlt.
qed.

lemma ftw_uniq_g (y : FTWES.msgFORSTW * index) :
  uniq (map (fun (x : int * int * int) => x.`2) (FTWES.g y)).
proof.
rewrite /FTWES.g /= map_mkseq /mkseq map_inj_in_uniq 2:iota_uniq.
move => u v _ _ /=. smt().
qed.

(* ==========================================================================
   THE M CLONE.  FORS_C10_Multi.MFORSC10 onto the concrete FTWES instance -- the
   carrier of the ITSR(+C)/C10 assumption game (M.F.ITSRC10 / O_ITSRC10_Default /
   Adv_ITSRC10) + the coverage machinery (hC).  mkeygen/fsign/fverify LEFT
   ABSTRACT (we do NOT use M's own multi-game -- Gproc replaces it); good_pos
   CARRIED.  d <- l.  Identical to rtop_c_vt_wip.ec:262-294.
   ========================================================================== *)
clone FORS_C10_Multi.MFORSC10 as M with
  type F.mkey    <- mkey,
  type F.msg     <- msg,
  type F.out_t   <- FTWES.msgFORSTW * index,
  op   F.k       <- k,
  op   F.a       <- a,
  op   F.dmkey   <- dmkey,
  op   F.mco     <- FTWES.mco,
  op   F.g       <- FTWES.g,
  type pseed     <- pseed,
  type adrs      <- adrs,
  type pkFORS    <- FTWES.pkFORS,
  type skFORS    <- FTWES.skFORS,
  type sigFORSTW <- FTWES.sigFORSTW,
  op   dpseed    <- dpseed,
  op   adz       <- adz,
  op   d         <- l

  proof F.ge1_k, F.ge1_a, F.dmkey_ll, F.size_g, F.eqiks_g, F.neqisvs_g,
        F.rng_g, F.uniq_g, ge1_d, dpseed_ll.
  realize F.ge1_k     by exact: ge1_k.
  realize F.ge1_a     by exact: ge1_a.
  realize F.dmkey_ll  by exact: dmkey_ll.
  realize F.size_g    by exact: ftw_size_g.
  realize F.eqiks_g   by exact: ftw_eqiks_g.
  realize F.neqisvs_g by exact: ftw_neqisvs_g.
  realize F.rng_g     by exact: ftw_rng_g.
  realize F.uniq_g    by exact: ftw_uniq_g.
  realize ge1_d       by smt(ge2_l).
  realize dpseed_ll   by exact: dpseed_ll.

(* THE +C BRIDGE (proven, orthogonal).  M.F.good IS good_fors; the two conditioned
   mk-draws are the same distribution.  Copied from rtop_c_vt_wip.ec:298-307. *)
lemma good_eq_good_fors_M (m : msg) (mk : mkey) : M.F.good m mk = good_fors m mk.
proof. by rewrite /M.F.good /M.F.predC_fors /good_fors. qed.

lemma dcond_good_eq (m : msg) :
  dcond dmkey (M.F.good m) = dcond dmkey (good_fors m).
proof. by congr; apply fun_ext => mk; exact good_eq_good_fors_M. qed.

(* ==========================================================================
   STEP 1 -- THE PROCEDURAL Gproc GAME.
   ========================================================================== *)

(* A Gproc FORS+C signature: (mk = R) + the tree-layer auth-path sig.  NO
   counter, NO hypertree part (that lives in the reduction R_fors_p, not here). *)
type sigGproc = mkey * FTWES.sigFORSTW.

(* -- Oracle interfaces -- *)
module type SOracle_CMA_Gproc = {
  proc sign(m : msg) : sigGproc
}.

module type Oracle_CMA_Gproc = {
  proc init(sks_init : FTWES.skFORS list list, ps_init : pseed, ad_init : adrs) : unit
  proc sign(m : msg) : sigGproc
  proc fresh(m : msg) : bool
}.

module type Adv_EUFCMA_Gproc (O : SOracle_CMA_Gproc) = {
  proc forge(pk : FTWES.pkFORS list list * pseed * adrs) : msg * sigGproc
}.

(* -- Procedural keygen: samples the nested cube ps-INDEPENDENTLY (byte-mirror of
      RtopCSoundness V_C.main:394-410) then precomputes the pkFORS POOL via
      gen_pkFORS (mirror MM45 M_FORS_ES_NPRF.keygen:1933-1980, nested nr_trees 0 x
      l' instead of s x l).  The public key is the pool; the secret is the cube. *)
module GprocKg = {
  proc keygen(ps : pseed, ad : adrs)
       : FTWES.pkFORS list list * FTWES.skFORS list list = {
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORScube : dgstblock list list;
    var skFORSlp : FTWES.skFORS list;
    var skFORSnt : FTWES.skFORS list list;
    var pkFORS : FTWES.pkFORS;
    var pkFORSlp : FTWES.pkFORS list;
    var pkFORSnt : FTWES.pkFORS list list;
    var skFORS : FTWES.skFORS;

    (* FORS key cube -- sampled ps-INDEPENDENTLY, byte-identical to V_C. *)
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

    (* Precompute the pkFORS pool (public key) via gen_pkFORS per instance. *)
    pkFORSnt <- [];
    while (size pkFORSnt < nr_trees 0) {
      pkFORSlp <- [];
      while (size pkFORSlp < l') {
        skFORS <- nth witness (nth witness skFORSnt (size pkFORSnt)) (size pkFORSlp);
        pkFORS <@ FTWES.FL_FORS_ES_NPRF.gen_pkFORS(skFORS, ps,
                    set_kpidx (set_tidx (set_typeidx ad trhftype)
                                        (size pkFORSnt)) (size pkFORSlp));
        pkFORSlp <- rcons pkFORSlp pkFORS;
      }
      pkFORSnt <- rcons pkFORSnt pkFORSlp;
    }

    return (pkFORSnt, skFORSnt);
  }
}.

(* -- Default CMA oracle: fresh CONDITIONED mk, NON-memoized, edivz-routed
      concrete FORS sign.  Byte-identical body to V_C.O_CMA_C.sign minus the
      HT-sign (which R_fors_p adds).  Mirror M.O_CMA_MFORSC10 with concrete route. *)
module O_CMA_Gproc : Oracle_CMA_Gproc = {
  var sks : FTWES.skFORS list list
  var ps  : pseed
  var ad  : adrs
  var qs  : msg list

  proc init(sks_init : FTWES.skFORS list list, ps_init : pseed, ad_init : adrs) : unit = {
    sks <- sks_init;
    ps  <- ps_init;
    ad  <- ad_init;
    qs  <- [];
  }

  proc sign(m : msg) : sigGproc = {
    var mk : mkey;
    var cm : FTWES.msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var skFORS : FTWES.skFORS;
    var sigFORSTW : FTWES.sigFORSTW;

    mk <$ dcond dmkey (good_fors m);
    (cm, idx) <- FTWES.mco mk m;
    (tidx, kpidx) <- edivz (Index.val idx) l';
    skFORS <- nth witness (nth witness sks tidx) kpidx;
    sigFORSTW <@ FTWES.FL_FORS_ES_NPRF.sign((skFORS, ps,
                   set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);

    qs <- rcons qs m;
    return (mk, sigFORSTW);
  }

  proc fresh(m : msg) : bool = {
    return ! (m \in qs);
  }
}.

(* -- The EUF-CMA game.  verify is CONCRETE:  predC_fors (mco mk' m') AND the
      reconstructed pkFORS equals the precomputed pool entry (routed by edivz).
      This is EXACTLY V_C's valid_MFORSC10 (pkFORS' = pool entry) conjoined with
      the +C forced-zero gate -- NOT a zeroable abstract op. *)
module EUF_CMA_Gproc (A : Adv_EUFCMA_Gproc, O : Oracle_CMA_Gproc) = {
  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pkFORSnt : FTWES.pkFORS list list;
    var skFORSnt : FTWES.skFORS list list;
    var m' : msg;
    var sig' : sigGproc;
    var mk' : mkey;
    var sigFORSTW' : FTWES.sigFORSTW;
    var cm : FTWES.msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var pkFORS' : FTWES.pkFORS;
    var is_valid, is_fresh : bool;

    ad <- adz;
    ps <$ dpseed;
    (pkFORSnt, skFORSnt) <@ GprocKg.keygen(ps, ad);

    O.init(skFORSnt, ps, ad);
    (m', sig') <@ A(O).forge((pkFORSnt, ps, ad));

    (mk', sigFORSTW') <- sig';
    (cm, idx) <- FTWES.mco mk' m';
    (tidx, kpidx) <- edivz (Index.val idx) l';

    pkFORS' <@ FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW(sigFORSTW', cm, ps,
                 set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

    is_valid <- M.F.predC_fors (FTWES.mco mk' m')
                /\ pkFORS' = nth witness (nth witness pkFORSnt tidx) kpidx;
    is_fresh <@ O.fresh(m');

    return is_valid /\ is_fresh;
  }
}.

(* ==========================================================================
   STEP 2 -- THE EUF-CMA BOUND FOR Gproc, RE-DERIVED to ITSR(+C)/C10.

   The BRIDGE is rejected (header); we RE-DERIVE the three FORS_C10_Multi lemmas
   over Gproc.  Each is its FORS_C10_Multi proof + a `sim` keygen prefix, because
   Gproc runs the identical sampling keygen on both sides and the covered/ts
   coupling is nesting-agnostic (the edivz routing is internal to sign, identical
   on both sides, and never enters the coupling invariant).
   ========================================================================== *)

(* Keygen runs identical sampling code on both sides -> couples by sim. *)
equiv keygen_eq :
  GprocKg.keygen ~ GprocKg.keygen : ={arg} ==> ={res}.
proof. proc; sim. qed.

(* The concrete FORS sign is a PROC (not the abstract op `fsign`), so oracle
   coupling must step through it: identical calls couple on equal args. *)
equiv forsnprf_sign_eq :
  FTWES.FL_FORS_ES_NPRF.sign ~ FTWES.FL_FORS_ES_NPRF.sign : ={arg} ==> ={res}.
proof. proc; sim. qed.

(* The +C HT signer is deterministic; V_C and R_fors_p BOTH sign on-the-fly, so the
   HT-sign couples as the IDENTITY (contrast LeqPr_VF_C, where RV precomputes sigl and
   the couple is via the nprf_sign_cf closed form). *)
equiv htsign_eq :
  FL_SL_XMSS_MT_C_ES_NPRF.sign ~ FL_SL_XMSS_MT_C_ES_NPRF.sign : ={arg} ==> ={res}.
proof. proc; sim. qed.

(* pkFORS_from_sigFORSTW terminates (bounded k-loop, no sampling): lossless.
   Same shape as RtopCSoundness.genpkfors_ll (body is pure, no inner call). *)
lemma pkfromsig_ll : islossless FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW.
proof.
proc; wp; while (true) (k - size roots).
+ move => z; auto; smt(size_rcons).
by auto; smt().
qed.

(* The two identical pkFORS_from_sigFORSTW calls couple on equal args. *)
equiv pkfromsig_eq :
  FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW ~ FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW
  : ={arg} ==> ={res}.
proof. proc; sim. qed.

(* -- Instrumented oracle: ghost target list `ts` (once per SIGNATURE, matching
      the non-memoized C10 oracle).  Mirror O_CMA_MFORSC10_I. *)
module O_CMA_Gproc_I : Oracle_CMA_Gproc = {
  var sks : FTWES.skFORS list list
  var ps  : pseed
  var ad  : adrs
  var qs  : msg list
  var ts  : (mkey * msg) list

  proc init(sks_init : FTWES.skFORS list list, ps_init : pseed, ad_init : adrs) : unit = {
    sks <- sks_init;
    ps  <- ps_init;
    ad  <- ad_init;
    qs  <- [];
    ts  <- [];
  }

  proc sign(m : msg) : sigGproc = {
    var mk : mkey;
    var cm : FTWES.msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var skFORS : FTWES.skFORS;
    var sigFORSTW : FTWES.sigFORSTW;

    mk <$ dcond dmkey (good_fors m);
    ts <- rcons ts (mk, m);                       (* ghost target, once per sign *)
    (cm, idx) <- FTWES.mco mk m;
    (tidx, kpidx) <- edivz (Index.val idx) l';
    skFORS <- nth witness (nth witness sks tidx) kpidx;
    sigFORSTW <@ FTWES.FL_FORS_ES_NPRF.sign((skFORS, ps,
                   set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);

    qs <- rcons qs m;
    return (mk, sigFORSTW);
  }

  proc fresh(m : msg) : bool = {
    return ! (m \in qs);
  }
}.

module EUF_CMA_Gproc_I (A : Adv_EUFCMA_Gproc) = {
  var covered : bool

  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pkFORSnt : FTWES.pkFORS list list;
    var skFORSnt : FTWES.skFORS list list;
    var m' : msg;
    var sig' : sigGproc;
    var mk' : mkey;
    var sigFORSTW' : FTWES.sigFORSTW;
    var cm : FTWES.msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var pkFORS' : FTWES.pkFORS;
    var is_valid, is_fresh : bool;

    ad <- adz;
    ps <$ dpseed;
    (pkFORSnt, skFORSnt) <@ GprocKg.keygen(ps, ad);

    O_CMA_Gproc_I.init(skFORSnt, ps, ad);
    (m', sig') <@ A(O_CMA_Gproc_I).forge((pkFORSnt, ps, ad));

    (mk', sigFORSTW') <- sig';
    (cm, idx) <- FTWES.mco mk' m';
    (tidx, kpidx) <- edivz (Index.val idx) l';

    pkFORS' <@ FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW(sigFORSTW', cm, ps,
                 set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

    is_valid <- M.F.predC_fors (FTWES.mco mk' m')
                /\ pkFORS' = nth witness (nth witness pkFORSnt tidx) kpidx;
    is_fresh <@ O_CMA_Gproc_I.fresh(m');

    covered <-
      all (fun x => x \in flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2)
                                       O_CMA_Gproc_I.ts))
          (M.F.hC sig'.`1 m');

    return is_valid /\ is_fresh;
  }
}.

(* Instrumentation is res-preserving (mirror eufcma_mforsc10_I_eq): the ghost `ts`
   and `covered` never feed a returned value; both sides run keygen_eq + the same
   conditioned draw. *)
lemma eufcma_gproc_I_eq
  (A <: Adv_EUFCMA_Gproc{-O_CMA_Gproc, -O_CMA_Gproc_I, -EUF_CMA_Gproc_I}) &m :
    Pr[EUF_CMA_Gproc(A, O_CMA_Gproc).main() @ &m : res]
  = Pr[EUF_CMA_Gproc_I(A).main() @ &m : res].
proof.
byequiv => //.
proc.
inline{1} O_CMA_Gproc.init O_CMA_Gproc.fresh.
inline{2} O_CMA_Gproc_I.init O_CMA_Gproc_I.fresh.
wp.
call pkfromsig_eq.
wp.
call (:   ={qs}(O_CMA_Gproc, O_CMA_Gproc_I)
       /\ O_CMA_Gproc.sks{1} = O_CMA_Gproc_I.sks{2}
       /\ O_CMA_Gproc.ps{1} = O_CMA_Gproc_I.ps{2}
       /\ O_CMA_Gproc.ad{1} = O_CMA_Gproc_I.ad{2}).
+ proc; wp; call forsnprf_sign_eq; auto.
wp.
call keygen_eq.
auto.
qed.

(* -- The multi->single ITSR(+C)/C10 reduction (mirror R_ITSRC10_MFORSC10,
      FORS_C10_Multi.ec:231, with procedural nested keygen + edivz routing).
      Generates the FORS cube/pool ITSELF (GprocKg.keygen), fetches per-signature
      CONDITIONED keys from the ITSRC10 oracle (non-memoized), routes by edivz,
      relays the forgery PAIR (mk', m'). *)
module (R_ITSRC10_Gproc (A : Adv_EUFCMA_Gproc) : M.F.Adv_ITSRC10)
       (O : M.F.Oracle_ITSRC10) = {
  var ps  : pseed
  var ad  : adrs
  var sks : FTWES.skFORS list list

  module O_CMA : SOracle_CMA_Gproc = {
    proc sign(m : msg) : sigGproc = {
      var mk : mkey;
      var cm : FTWES.msgFORSTW;
      var idx : index;
      var tidx, kpidx : int;
      var skFORS : FTWES.skFORS;
      var sigFORSTW : FTWES.sigFORSTW;

      mk <@ O.query(m);                     (* ITSR(+C)/C10 oracle: conditioned + record *)
      (cm, idx) <- FTWES.mco mk m;
      (tidx, kpidx) <- edivz (Index.val idx) l';
      skFORS <- nth witness (nth witness sks tidx) kpidx;
      sigFORSTW <@ FTWES.FL_FORS_ES_NPRF.sign((skFORS, ps,
                     set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);

      return (mk, sigFORSTW);
    }
  }

  proc find() : mkey * msg = {
    var pkFORSnt : FTWES.pkFORS list list;
    var m' : msg;
    var sig' : sigGproc;

    ad <- adz;
    ps <$ dpseed;
    (pkFORSnt, sks) <@ GprocKg.keygen(ps, ad);

    (m', sig') <@ A(O_CMA).forge((pkFORSnt, ps, ad));

    return (sig'.`1, m');
  }
}.

(* The ITSR(+C)/C10 hop: the COVERAGE part of Gproc EUF-CMA is caught by
   ITSR(+C)/C10 through R_ITSRC10_Gproc.  Mirror ITSRC10_hop_M. *)
lemma ITSRC10_hop_Gproc
  (A <: Adv_EUFCMA_Gproc{-R_ITSRC10_Gproc, -O_CMA_Gproc_I, -M.F.O_ITSRC10_Default, -EUF_CMA_Gproc_I}) &m :
    Pr[EUF_CMA_Gproc_I(A).main() @ &m : res /\ EUF_CMA_Gproc_I.covered]
  <= Pr[M.F.ITSRC10(R_ITSRC10_Gproc(A), M.F.O_ITSRC10_Default).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> (res{1} /\ EUF_CMA_Gproc_I.covered{1}) => res{2}) => //.
proc.
inline{2} R_ITSRC10_Gproc(A, M.F.O_ITSRC10_Default).find.
inline{2} M.F.O_ITSRC10_Default.init M.F.O_ITSRC10_Default.get_targets.
inline{1} O_CMA_Gproc_I.init O_CMA_Gproc_I.fresh.
swap{2} 1 2.
wp.
call{1} pkfromsig_ll.
wp.
call (:   O_CMA_Gproc_I.sks{1} = R_ITSRC10_Gproc.sks{2}
       /\ O_CMA_Gproc_I.ps{1} = R_ITSRC10_Gproc.ps{2}
       /\ O_CMA_Gproc_I.ad{1} = R_ITSRC10_Gproc.ad{2}
       /\ O_CMA_Gproc_I.ts{1} = M.F.O_ITSRC10_Default.ts{2}
       /\ (forall x, x \in map (fun (km : mkey * msg) => km.`2)
                             O_CMA_Gproc_I.ts{1}
                     => x \in O_CMA_Gproc_I.qs{1})).
+ proc.
  inline{2} M.F.O_ITSRC10_Default.query.
  wp; call forsnprf_sign_eq; auto => />.
  smt(map_rcons mem_rcons).
wp.
call keygen_eq.
auto => />.
rewrite /hC /=.
smt(allP mapP mem_rcons).
qed.

(* THEOREM (Gproc d-EU-CMA, C10-faithful).  Mirror EUFCMA_MFORSC10.  RHS ITSRC10
   term is the SAME carried M.F.ITSRC10 assumption; the mtree premise is carried
   exactly as FORS_C10_Multi does. *)
lemma EUFCMA_Gproc
  (A <: Adv_EUFCMA_Gproc{-R_ITSRC10_Gproc, -O_CMA_Gproc, -O_CMA_Gproc_I,
                         -M.F.O_ITSRC10_Default, -EUF_CMA_Gproc_I})
  (mtree_openpre mtree_trh mtree_trco : real)
  &m :
    (   Pr[EUF_CMA_Gproc_I(A).main() @ &m : res /\ !EUF_CMA_Gproc_I.covered]
     <= mtree_openpre + mtree_trh + mtree_trco) =>
    Pr[EUF_CMA_Gproc(A, O_CMA_Gproc).main() @ &m : res]
  <=   Pr[M.F.ITSRC10(R_ITSRC10_Gproc(A), M.F.O_ITSRC10_Default).main() @ &m : res]
     + mtree_openpre + mtree_trh + mtree_trco.
proof.
move=> htree.
rewrite (eufcma_gproc_I_eq A &m).
rewrite Pr[mu_split EUF_CMA_Gproc_I.covered].
have hop := ITSRC10_hop_Gproc A &m.
smt().
qed.

(* ==========================================================================
   STEP 3 -- hop5:  Pr[V_C : res /\ valid_MFORSC10]  <=  Pr[Gproc EUF(R_fors_p F)].

   R_fors_p: the VT-branch reduction (mirror rtop_c_vt_wip.R_fors, retyped to the
   CONCRETE Gproc oracle + NESTED edivz routing).  Pre-generate the WOTS/HT keys
   via the +C keygen (root handed to F), DELEGATE the FORS mk-draw + tree-sign to
   the Gproc game oracle O.sign (which draws mk <$ dcond dmkey (good_fors m) and
   returns (mk, sigFORSTW)), HT-sign locally over the GAME-PROVIDED pkFORS POOL
   (nth-nth, edivz), and on F's forgery extract the FORS+C forgery pair
   (mk', sigFORSTW').
   ========================================================================== *)
module (R_fors_p (A : Adv_EUFCMA_C) : Adv_EUFCMA_Gproc)
       (O : SOracle_CMA_Gproc) = {
  var pks : FTWES.pkFORS list list
  var ps  : pseed
  var ad  : adrs
  var skWOTStd : skWOTS list list list

  module O_CMA : SOracle_CMA_C = {
    proc sign(m : msg) : sigSPHINCSPLUSTWC = {
      var mk : mkey;
      var sigFORSTW : FTWES.sigFORSTW;
      var cm : FTWES.msgFORSTW;
      var idx : index;
      var tidx, kpidx : int;
      var pkFORS : FTWES.pkFORS;
      var sigHT : sigFLSLXMSSMTTWC;

      (mk, sigFORSTW) <@ O.sign(m);                 (* Gproc oracle: mk-draw + FORS-sign *)

      (cm, idx) <- FTWES.mco mk m;
      (tidx, kpidx) <- edivz (Index.val idx) l';
      pkFORS <- nth witness (nth witness pks tidx) kpidx;   (* game pool, nested *)

      sigHT <@ FL_SL_XMSS_MT_C_ES_NPRF.sign((skWOTStd, ps, ad), pkFORS, idx);

      return (mk, sigFORSTW, sigHT);
    }
  }

  proc forge(pk : FTWES.pkFORS list list * pseed * adrs) : msg * sigGproc = {
    var pkHT : pkFLSLXMSSMTTW;
    var skHT : skWOTS list list list * pseed * adrs;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTWC;
    var mk' : mkey;
    var sigFORSTW' : FTWES.sigFORSTW;
    var sigHT' : sigFLSLXMSSMTTWC;
    var root : dgstblock;

    (pks, ps, ad) <- pk;

    (pkHT, skHT) <@ FL_SL_XMSS_MT_C_ES_NPRF.keygen(ps, ad);
    skWOTStd <- skHT.`1;
    root <- pkHT.`1;

    (m', sig') <@ A(O_CMA).forge((root, ps));

    (mk', sigFORSTW', sigHT') <- sig';

    return (m', (mk', sigFORSTW'));
  }
}.

(* -- Closed-form of the deterministic FORS pk recompute (= genpkfors_cf's post,
      RtopCSoundness :925).  Used to state the pool invariant: after GprocKg.keygen
      the RHS pool entry (i,j) EQUALS pkFORS_cf of the (shared) cube entry at the
      per-instance FORS address.  Because Gproc indexes the pool NESTED (nth-nth, at
      (tidx,kpidx)) -- never flattened -- the establish address (i,j) and the consume
      address (tidx,kpidx) are the SAME syntactic expression, so NO getsettrhf_kpidx
      collapse / genpkfors_flatten is needed (contrast LeqPr_VF_C). *)
op pkFORS_cf (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) : FTWES.pkFORS =
  trco ps0 (set_kpidx (set_typeidx ad0 trcotype) (FTWES.get_kpidx ad0))
    (flatten (map DigestBlock.val
       (mkseq (fun (u : int) =>
          FTWES.val_bt_trh ps0 ad0
            (list2tree (mkseq (fun (v : int) =>
               f ps0 (set_thtbidx ad0 0 (u * t + v))
                 (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skF) u) v))) t)) u) k))).

(* genpkfors_cf phrased with the pkFORS_cf name (= RtopCSoundness.genpkfors_cf). *)
lemma genpkfors_cf_named (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) :
  phoare[FTWES.FL_FORS_ES_NPRF.gen_pkFORS :
        skFORS = skF /\ ps = ps0 /\ ad = ad0 ==> res = pkFORS_cf skF ps0 ad0] = 1%r.
proof. by rewrite /pkFORS_cf; conseq (genpkfors_cf skF ps0 ad0). qed.

(* edivz routing bounds (= genpkfors_flatten's hi/hj, RtopCSoundness :973-977):
   the FORS (tree,keypair) indices land in range, so the pool invariant applies. *)
lemma tk_bounds (ix : index) :
     0 <= Index.val ix %/ l' < nr_trees 0
  /\ 0 <= Index.val ix %% l' < l'.
proof.
split; last by smt(ge2_lp Index.valP).
split; 1: by rewrite divz_ge0; smt(ge2_lp Index.valP).
rewrite /nr_trees /l' ltz_divLR; 1: smt(ge2_lp).
by rewrite -exprD_nneg /= 1:mulr_ge0; smt(ge1_hp ge1_d Index.valP).
qed.

(* The V-side inlined HT root recompute (root_from_sigC) is ONE-SIDED at the tail
   (Gproc is FORS-only, no HT verify); its (root',allOkC) feed only the DROPPED HT
   validity conjunct, so we one-side it via losslessness (bounded d-loop, no rnd). *)
lemma pkwsigc_ll : islossless FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C.
proof.
proc; wp; while (true) (len - size pkWOTS_l).
+ move => z; auto; smt(size_rcons).
by auto; smt().
qed.

lemma rootfromsigc_ll : islossless FL_SL_XMSS_MT_C_ES.root_from_sigC.
proof.
proc; wp; while (true) (d - i).
+ move => z; wp; call pkwsigc_ll; auto; smt().
by auto; smt().
qed.

(* hop5: the VT branch bound against the CONCRETE procedural game Gproc.  This is
   the SOUND replacement for rtop_c_vt_wip.LeqPr_VT_C (which was admitted against
   the ABSTRACT M -- D1/D2).  Mirror MM45 LeqPr_..._VT_MFORSTWESNPRF
   (SPHINCS_PLUS.ec:3129-3467). *)
lemma LeqPr_VT_C_proc
  (F <: Adv_EUFCMA_C{-R_fors_p, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V, -O_CMA_Gproc}) &m :
    Pr[EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V(F).main() @ &m :
         res /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.valid_MFORSC10]
  <=
    Pr[EUF_CMA_Gproc(R_fors_p(F), O_CMA_Gproc).main() @ &m : res].
proof.
(* ------------------------------------------------------------------------
   RESIDUAL (PRECISE).  This is a byequiv V_C(F) ~ EUF_CMA_Gproc(R_fors_p(F)):
   the MM45 VT-coupling (SPHINCS_PLUS.ec:3129-3467) transcribed to +C.  It is
   GRIND, NOT a structural obstruction (the 3 diagnosed obstructions D1 fverify /
   D2 keygen / tape-in-ps are ALL resolved by Gproc's construction, Steps 1-2):

     (i)  keygen+pool coupling.  Couple V_C's inline cube sampling (RtopCSoundness
          :394-410) with GprocKg.keygen's cube loop (BYTE-IDENTICAL -> sim/while),
          then GprocKg's pool loop is one-sided (while{2}) establishing the
          trcoINV pool invariant via `call{2} genpkfors_cf` (the gen_pkFORS closed
          form -- SIMPLER than MM45/R_top_C's inlined tree hash, which needs the
          ~150-line nodes-loop arithmetic RtopCSoundness :1184-1400).  REUSE:
          genpkfors_cf, getsettrhf_kpidx (get_kpidx collapse), DBLLKTL.insubdK.
     (ii) HT keygen couple: keygenC_eq (RtopCSoundness :559, PROVEN).
     (iii)oracle coupling V_C.O_CMA_C.sign ~ R_fors_p.O_CMA.sign: identical except
          V_C computes pkFORS via gen_pkFORS on-the-fly while R uses the pool entry
          nth-nth -- EQUAL by trcoINV + genpkfors_flatten (RtopCSoundness :947,
          PROVEN); the FORS mk-draw+sign couples via O.sign; HT-sign identical.
     (iv) forge extraction / event map: (res{1} /\ valid_MFORSC10{1}) => res{2}.
          V_C is_valid's good_fors m' mk' = M.F.predC_fors(mco mk' m') (Gproc
          verify's gate, via good_eq_good_fors_M); V_C valid_MFORSC10 (pkFORS'=
          gen_pkFORS(skFORS)) => Gproc pool-eq (pkFORS'=pool entry) via trcoINV;
          freshness qs coincides (R relays F's queries through O.sign).  The +C
          mk-rnd bite uses dcond_good_eq (both PROVEN above).
   NO new axiom; NON-VACUITY gate for this lemma = the VT-event canary flip
   (valid_MFORSC10 negated must be REJECTED).  Every cited asset is CERTIFIED-
   0-ADMIT in RtopCSoundness / this file.  This admit is a TRANSCRIPTION residual,
   NOT a modelling seam (contrast rtop_c_vt_wip.LeqPr_VT_C, which was admitted
   against the ABSTRACT M where D1/D2 make it unprovable-or-vacuous). *)
byequiv => //.
proc.
inline{2} O_CMA_Gproc.init O_CMA_Gproc.fresh.
inline{2} R_fors_p(F, O_CMA_Gproc).forge.
inline{2} GprocKg.keygen.
(* ===== opening: ad, ps ===== *)
seq 2 2 : (={glob F} /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz /\ ad{2} = adz).
+ auto.
(* ===== cube: byte-identical raw ddgstblock sampling -> nested relational whiles ===== *)
seq 2 4 : (={glob F} /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz /\ ad{2} = adz
           /\ ps0{2} = ps{2} /\ ad0{2} = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = skFORSnt0{2}).
+ while (={glob F} /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = ps{2} /\ ps0{2} = ps{2}
        /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz /\ ad{2} = adz /\ ad0{2} = adz
        /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = skFORSnt0{2}).
  - wp.
    while (={glob F, skFORSlp} /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = ps{2} /\ ps0{2} = ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz /\ ad{2} = adz /\ ad0{2} = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = skFORSnt0{2}).
    * wp.
      while (={glob F, skFORScube, skFORSlp} /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = ps{2} /\ ps0{2} = ps{2}
             /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz /\ ad{2} = adz /\ ad0{2} = adz
             /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = skFORSnt0{2}).
      + wp.
        while (={glob F, skFORSet, skFORScube, skFORSlp} /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = ps{2} /\ ps0{2} = ps{2}
               /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz /\ ad{2} = adz /\ ad0{2} = adz
               /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = skFORSnt0{2}).
        - wp; rnd; skip => />.
        wp; skip => />.
      wp; skip => />.
    wp; skip => />.
  wp; skip => />.
(* ===== pool: one-sided while{2} building pkFORSnt0[i][j] = pkFORS_cf(sk[i][j]) ===== *)
seq 0 2 : (={glob F} /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz /\ ad{2} = adz
           /\ ps0{2} = ps{2} /\ ad0{2} = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = skFORSnt0{2}
           /\ size pkFORSnt0{2} = nr_trees 0
           /\ all ((=) l' \o size) pkFORSnt0{2}
           /\ (forall (i j : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
                 nth witness (nth witness pkFORSnt0{2} i) j
                 = pkFORS_cf (nth witness (nth witness skFORSnt0{2} i) j) ps{2}
                             (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j))).
+ while{2} (ps0{2} = ps{2} /\ ad0{2} = adz
            /\ 0 <= size pkFORSnt0{2} <= nr_trees 0
            /\ all ((=) l' \o size) pkFORSnt0{2}
            /\ (forall (i j : int), 0 <= i < size pkFORSnt0{2} => 0 <= j < l' =>
                  nth witness (nth witness pkFORSnt0{2} i) j
                  = pkFORS_cf (nth witness (nth witness skFORSnt0{2} i) j) ps{2}
                              (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)))
           (nr_trees 0 - size pkFORSnt0{2}).
  - move => &m0 z.
    wp.
    while (ps0 = ps /\ ad0 = adz
           /\ size pkFORSnt0 < nr_trees 0
           /\ 0 <= size pkFORSlp <= l'
           /\ (forall (j : int), 0 <= j < size pkFORSlp =>
                 nth witness pkFORSlp j
                 = pkFORS_cf (nth witness (nth witness skFORSnt0 (size pkFORSnt0)) j) ps
                             (set_kpidx (set_tidx (set_typeidx adz trhftype) (size pkFORSnt0)) j))
           /\ (forall (i j : int), 0 <= i < size pkFORSnt0 => 0 <= j < l' =>
                 nth witness (nth witness pkFORSnt0 i) j
                 = pkFORS_cf (nth witness (nth witness skFORSnt0 i) j) ps
                             (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)))
          (l' - size pkFORSlp).
    * move => z'.
      wp.
      exists* pkFORSnt0, pkFORSlp, skFORSnt0, ps0, ad0; elim* => pkntv pklpv skntv ps0v ad0v.
      call (genpkfors_cf_named (nth witness (nth witness skntv (size pkntv)) (size pklpv)) ps0v
                               (set_kpidx (set_tidx (set_typeidx ad0v trhftype) (size pkntv)) (size pklpv))).
      wp; skip => /> ltnt ge0 lelp nthlp nthnt ltlp.
      rewrite !size_rcons.
      split; 2: smt().
      split; 1: smt(size_ge0).
      move => j ge0j ltj1.
      rewrite nth_rcons; case (j < size pklpv) => [ltj | /lezNgt gej]; 1: smt().
      by rewrite (: j = size pklpv) 1:/# /=.
    wp; skip => /> &hr ge0 lent allpk nthnt ltnt.
    split; 1: smt(ge2_lp).
    move => pkflp; split => [_ ?|]; 1: smt().
    move => geflp ge0flp leflp nthlp.
    rewrite !size_rcons.
    split; 2: smt().
    split; 1: smt(size_ge0).
    split.
    * rewrite -cats1 all_cat allpk /=.
      by rewrite /(\o) /=; smt().
    move => i j ge0i lti1 ge0j ltj.
    rewrite nth_rcons; case (i < size pkFORSnt0{hr}) => [lti | /lezNgt gei]; 1: smt().
    have -> : i = size pkFORSnt0{hr} by smt().
    by rewrite /=; smt().
  wp; skip => /> &2.
  split; 1: smt(ge2_l ge1_hp ge1_d IntOrder.expr_ge0).
  move => pkfnt; split; 1: by move => *; smt().
  move => genr ge0nr lenr allpk nthnt.
  have szeq : size pkfnt = nr_trees 0 by smt().
  split; 1: exact szeq.
  move => i j ge0i ltinr ge0j ltjl; apply nthnt; smt().
(* ===== deterministic setup (binds/init/pk/R-assign) + HT keygen (keygenC_eq2) ===== *)
seq 4 13 : (={glob F}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{1} = R_fors_p.skWOTStd{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = O_CMA_Gproc.sks{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = O_CMA_Gproc.ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = R_fors_p.ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz
           /\ ad{2} = adz
           /\ O_CMA_Gproc.ad{2} = adz
           /\ R_fors_p.ad{2} = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.root{1} = root{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.qs{1} = O_CMA_Gproc.qs{2}
           /\ pkFORSnt{2} = R_fors_p.pks{2}
           /\ size R_fors_p.pks{2} = nr_trees 0
           /\ all ((=) l' \o size) R_fors_p.pks{2}
           /\ (forall (i j : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
                 nth witness (nth witness R_fors_p.pks{2} i) j
                 = pkFORS_cf (nth witness (nth witness O_CMA_Gproc.sks{2} i) j) O_CMA_Gproc.ps{2}
                             (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j))).
+ wp.
  exists* EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1}, EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1}; elim* => psv adv.
  call (keygenC_eq2 psv adv).
  wp; skip => />.
(* ===== reshape the post: HT-validity of is_valid{1} + the fresh timing are mapped/
   dropped; only good_fors (-> predC_fors) + pool-eq survive. ===== *)
conseq (: _ ==>
     (EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.valid_MFORSC10{1} => is_valid{1} => is_valid{2})
  /\ is_fresh{1} = is_fresh{2}); 1: smt().
(* ===== forge + deterministic prefix (extract / mco / edivz / skFORS) ===== *)
seq 5 6 : (   EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{1} = R_fors_p.skWOTStd{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = R_fors_p.ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz
           /\ ad{2} = adz
           /\ R_fors_p.ad{2} = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.qs{1} = O_CMA_Gproc.qs{2}
           /\ pkFORSnt{2} = R_fors_p.pks{2}
           /\ size R_fors_p.pks{2} = nr_trees 0
           /\ all ((=) l' \o size) R_fors_p.pks{2}
           /\ (forall (i j : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
                 nth witness (nth witness R_fors_p.pks{2} i) j
                 = pkFORS_cf (nth witness (nth witness EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} i) j) EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1}
                             (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j))
           /\ ={mk', m', sigFORSTW', cm, idx, tidx, kpidx}
           /\ skFORS{1} = nth witness (nth witness EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} tidx{1}) kpidx{1}
           /\ 0 <= Index.val idx{1} < l
           /\ tidx{1} = Index.val idx{1} %/ l'
           /\ kpidx{1} = Index.val idx{1} %% l').
+ wp.
  call (:   EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{1} = R_fors_p.skWOTStd{2}
         /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = O_CMA_Gproc.sks{2}
         /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = O_CMA_Gproc.ps{2}
         /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = R_fors_p.ps{2}
         /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz
         /\ O_CMA_Gproc.ad{2} = adz
         /\ R_fors_p.ad{2} = adz
         /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.qs{1} = O_CMA_Gproc.qs{2}
         /\ size R_fors_p.pks{2} = nr_trees 0
         /\ all ((=) l' \o size) R_fors_p.pks{2}
         /\ (forall (i j : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
               nth witness (nth witness R_fors_p.pks{2} i) j
               = pkFORS_cf (nth witness (nth witness O_CMA_Gproc.sks{2} i) j) O_CMA_Gproc.ps{2}
                           (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j))).
  + (* oracle body: V_C.O_CMA_C.sign ~ R_fors_p.O_CMA.sign *)
    proc.
    inline{2} O_CMA_Gproc.sign.
    (* Phase A: {2} inline adds m0<-m + renames O.sign locals to *0; couple mk-rnd +
       prefix + FORS-sign.  {1}[1-5] ~ {2}[1-6] (the extra {2} stmt = m0<-m). *)
    seq 5 6 : (   EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{1} = R_fors_p.skWOTStd{2}
               /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = O_CMA_Gproc.sks{2}
               /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = O_CMA_Gproc.ps{2}
               /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = R_fors_p.ps{2}
               /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz
               /\ O_CMA_Gproc.ad{2} = adz
               /\ R_fors_p.ad{2} = adz
               /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.qs{1} = O_CMA_Gproc.qs{2}
               /\ size R_fors_p.pks{2} = nr_trees 0
               /\ all ((=) l' \o size) R_fors_p.pks{2}
               /\ (forall (i j : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
                     nth witness (nth witness R_fors_p.pks{2} i) j
                     = pkFORS_cf (nth witness (nth witness O_CMA_Gproc.sks{2} i) j) O_CMA_Gproc.ps{2}
                                 (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j))
               /\ m{1} = m{2} /\ m0{2} = m{2} /\ mk{1} = mk0{2} /\ cm{1} = cm0{2} /\ idx{1} = idx0{2}
               /\ tidx{1} = tidx0{2} /\ kpidx{1} = kpidx0{2}
               /\ skFORS{1} = skFORS{2} /\ sigFORSTW{1} = sigFORSTW0{2}
               /\ idx0{2} = (FTWES.mco mk0{2} m{2}).`2
               /\ skFORS{1} = nth witness (nth witness O_CMA_Gproc.sks{2} tidx{1}) kpidx{1}
               /\ 0 <= Index.val idx{1} < l
               /\ tidx{1} = Index.val idx{1} %/ l'
               /\ kpidx{1} = Index.val idx{1} %% l').
    + sp 0 1.
      wp; call forsnprf_sign_eq; wp; rnd; skip => />; smt(Index.valP tk_bounds).
    (* Phase B: move {2} mid-body qs-append to the end, one-side V's gen_pkFORS = pool
       entry, couple the HT sign, couple the two qs-appends. *)
    swap{2} 1 5.
    wp.
    call htsign_eq.
    exists* skFORS{1}, EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1}, tidx{1}, kpidx{1}; elim* => skFv psv tiv kiv.
    call{1} (genpkfors_cf_named skFv psv (set_kpidx (set_tidx (set_typeidx adz trhftype) tiv) kiv)).
    wp; skip => /> &2 szpk allpk poolinv *.
    have [hi hj] := tk_bounds (FTWES.mco mk0{2} m{2}).`2.
    have hp := poolinv (Index.val (FTWES.mco mk0{2} m{2}).`2 %/ l')
                       (Index.val (FTWES.mco mk0{2} m{2}).`2 %% l') _ _; 1,2: smt().
    smt().
  skip => /> &1 &2 *.
  smt(tk_bounds Index.valP).
(* ===== backward tail: is_fresh/is_valid, one-side root_from_sigC, couple
   pkFORS_from_sig, one-side gen_pkFORS, event map ===== *)
wp.
call{1} rootfromsigc_ll.
wp.
call pkfromsig_eq.
exists* skFORS{1}, EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1}, tidx{1}, kpidx{1}; elim* => skFv psv tiv kiv.
call{1} (genpkfors_cf_named skFv psv (set_kpidx (set_tidx (set_typeidx adz trhftype) tiv) kiv)).
skip => /> &1 &2 szpk allpk poolinv ge0v ltv.
have [hi hj] := tk_bounds idx{2}.
have hp := poolinv (Index.val idx{2} %/ l') (Index.val idx{2} %% l') _ _; 1,2: smt().
move => *; smt().
qed.

(* ==========================================================================
   TIER 1, BRICK 1 (2026-08-03) — THE UNCOVERED WITNESS.

   WHERE THIS SITS.  `EUFCMA_Gproc` above proves the COVERED half of the Gproc
   EUF-CMA split (via ITSRC10_hop_Gproc) and CARRIES the UNCOVERED half

       Pr[EUF_CMA_Gproc_I(A) : res /\ !covered] <= mtree_openpre + mtree_trh + mtree_trco

   as a premise over forall-bound reals.  That premise -- (H-TREE-MULTI), stated
   at FORS_C10_Multi.ec:455-470 -- is the single term that keeps the deployed
   bound compatible with 1, and discharging it means PORTING MM45's tree layer
   (R_FSMDTOpenPRE_EUFCMA / R_TRHSMDTTCRC_EUFCMA / R_TRCOSMDTTCRC_EUFCMA over
   d*k*t targets) to this game.  MM45 proves the same half at FORS_ES.ec:3829
   (EUFCMA_MFORSTWESNPRF_OPRE, `local`) and :6531 (public), but the C10 FORS leg
   is a PARALLEL construction -- M.F is `clone FORS_C10.FORSC10`, not a clone of
   MM45's FORS_ES -- so the theorem is not reachable by routing.  It is a port.

   WHAT THIS BRICK IS.  The entry point of that port: from `!covered` it names
   the tuple the OpenPRE reduction has to hand to its challenger -- an element of
   the forgery's index set that was NEVER a target.  No new assumption; pure list
   reasoning about the ghost state EUF_CMA_Gproc_I already records.

   WHAT IT IS NOT: it bounds nothing.  It converts a negated `all` into an
   explicit witness, which is the first thing the reduction needs and the last
   thing that can be done without building the reduction modules.
   ========================================================================== *)
lemma Gproc_uncovered_gives_witness (ts : (mkey * msg) list) (mk : mkey) (m : msg) :
    ! all (fun x => x \in flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2) ts))
          (M.F.hC mk m)
  => exists x, x \in M.F.hC mk m
            /\ ! (x \in flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2) ts)).
proof.
  rewrite -has_predC hasP => -[x [hx hpx]].
  by exists x.
qed.


(* ==========================================================================
   TIER 1, BRICK 2 (2026-08-03) — THE SK-CUBE CORRESPONDENCE.

   `GprocKg.keygen` is STRUCTURALLY the loop fission of
   `FTWES.M_FORS_ES_NPRF.keygen` -- but only the SK half of that equivalence is
   proved here, so do not read the word "fission" as done: the
   left samples the whole FORS secret-key cube and then computes the public pool
   in a second pass; MM45 interleaves the two per instance.  For the SECRET half
   the two agree, and that is the half a reduction consumes -- it needs the key
   material to correspond and can recompute the pool.

   Everything that makes them comparable was CHECKED, not assumed:
     * loop bounds coincide -- the FTWES clone (SPHINCS_PLUS.ec:509) binds
       `op l <- l'` and `op s <- nr_trees 0`, literally GprocKg's bounds;
     * addresses coincide -- the same clone binds `op trhtype <- trhftype`.
       CAVEAT (round 14, Kimi K3 and Opus 5, independently): THIS EQUIV DOES NOT
       WITNESS THAT.  Key generation is address-independent (`gen_skFORS` takes
       no address) and both pk computations are pushed one-sided, so a future
       address-order swap would not break this lemma.  The fact is right by
       inspection; the evidence for it is inspection, not this proof;
     * `FL_FORS_ES_NPRF.gen_pkFORS` contains NO sampling;
     * all randomness is the single `<$ ddgstblock` in `gen_skFORS`.
   So no parameter side conditions are needed, and both deterministic pk
   computations are pushed out of the way in opposite directions: the RIGHT's
   from inside the synchronised loop, the LEFT's as a trailing one-sided nest.
   The three losslessness lemmas below exist for exactly those two discharges;
   none of them was in the base.

   WHAT THIS IS NOT.  It says nothing about the PUBLIC pool: relating those needs
   `gen_pkFORS` characterised as a FUNCTION of (skFORS, ps, ad), because EasyCrypt
   cannot hoist a computation out of a loop without naming its result.  That is
   the fission proper and it remains open.  It also says nothing about signing --
   the oracle and forge sites are INERT in this development
   (XmssmtCC_All.ec:9539-9541), so the correspondence bought here is key material
   only.
   ========================================================================== *)

(* --- prerequisites, proved in scratch/tier1_ll.ec --- *)

(* THE LOSSLESSNESS FACTS THESE DISCHARGES NEED ALREADY EXISTED.
   Round 14 (Kimi K3): `genleaves_ll` and `genpkfors_ll` are at
   RtopCSoundness.ec:911-923 with essentially identical proofs, and this file
   ALREADY does `require import RtopCSoundness` (:57) -- so they were in scope
   while I was re-proving them.  My header claimed "none of them was in the
   base": literally true of base-c10-split and misleading, since it implied they
   were needed.  The duplicates are gone and the originals are used.
   The third, `ftwes_gen_skFORS_ll`, was ALSO removed: Opus 5 found it had zero
   uses closure-wide -- `gen_skFORS` is inlined, not called -- so it was an
   orphan of exactly the kind Tier 0 was written to eliminate. *)

equiv GprocKg_sk_eq :
  GprocKg.keygen ~ FTWES.M_FORS_ES_NPRF.keygen :
    ={ps, ad} ==> res{1}.`2 = res{2}.`2.`1.
proof.
proc.
inline{2} FTWES.FL_FORS_ES_NPRF.gen_skFORS.
(* initialisations: left 1 statement, right 2 *)
seq 1 2 : (={ps, ad} /\ skFORSnt{1} = [] /\ skFORSs{2} = []).
+ by auto.
(* the sk nests, isolated so each side's loop is the last instruction *)
seq 1 1 : (={ps, ad} /\ skFORSnt{1} = skFORSs{2}).
+ while (={ps, ad} /\ skFORSnt{1} = skFORSs{2}).
  - wp.
    while (={ps, ad} /\ skFORSnt{1} = skFORSs{2} /\ skFORSlp{1} = skFORSl{2}).
    * wp.
      call{2} genpkfors_ll.
      wp.
      while (={ps, ad} /\ skFORScube{1} = skFORS0{2}).
      + wp.
        while (={ps, ad} /\ skFORSet{1} = skFORSt{2}).
        - by auto.
        by auto.
      by auto.
    by auto.
  by auto.
(* left still has its trailing pk nest; right only assignments *)
sp 1 2.
while{1} (true) (nr_trees 0 - size pkFORSnt{1}).
+ move=> &2 z.
  wp.
  while (true) (l' - size pkFORSlp).
  - move=> z'.
    wp; call genpkfors_ll; auto => />; smt(size_rcons).
  by wp; skip => />; smt(size_ge0 size_rcons ge2_lp).
by skip => />; smt(size_ge0 size_rcons).
qed.


(* ==========================================================================
   TIER 1, BRICK 2b — THE PK POOL AS A FUNCTION OF THE SK POOL.

   `GprocKg.keygen` is the loop fission of `FTWES.M_FORS_ES_NPRF.keygen`: the
   left samples the whole FORS secret-key cube and then computes the public pool
   in a second pass, MM45 interleaves them.  Brick 2a proved the SECRET halves
   agree.  These four results characterise each side's PUBLIC pool as the same
   pointwise function of its secret pool, which is what the fission needs.

   I claimed this step needed `gen_pkFORS` characterised as a function and called
   it the wall.  It was ALREADY characterised -- `genpkfors_cf_h`
   (RtopCSoundness.ec:875) -- in a file this one already imports.  That is the
   third time in this track I have blocked on, or re-derived, something sitting
   in an imported file.

   WHAT IS NOT HERE: the final combination
     conseq GprocKg_sk_eq <A> <B>
   which would give `res{1}.`1 = res{2}.`1.`1` outright.  `conseq` leaves FIVE
   subgoals and they need to be discharged individually; not done.  So the pk
   pools are each pinned to a function of their sk pool, and the last step from
   there to pool EQUALITY is open.
   ========================================================================== *)

(* The closed form, named once so both sides can be stated against it. *)
op pkfors_of (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) : FTWES.pkFORS =
  trco ps0 (set_kpidx (set_typeidx ad0 trcotype) (FTWES.get_kpidx ad0))
       (flatten (map DigestBlock.val
          (mkseq (fun (u : int) =>
             FTWES.val_bt_trh ps0 ad0
               (list2tree (fors_leaves_op_cube skF ps0 ad0 u)) u) k))).

lemma genpkfors_cf_op (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) :
  phoare[FTWES.FL_FORS_ES_NPRF.gen_pkFORS :
         skFORS = skF /\ ps = ps0 /\ ad = ad0 ==> res = pkfors_of skF ps0 ad0] = 1%r.
proof. by rewrite /pkfors_of; apply (genpkfors_cf skF ps0 ad0). qed.

(* --- B: after MM45's keygen, the pk pool is F of the sk pool, pointwise. --- *)
lemma MM45_keygen_pk_from_sk (psi : pseed) (adi : adrs) :
  hoare[FTWES.M_FORS_ES_NPRF.keygen :
        ps = psi /\ ad = adi
        ==> size res.`1.`1 = nr_trees 0
         /\ size res.`2.`1 = nr_trees 0
         /\ (forall i, 0 <= i < nr_trees 0 =>
               size (nth witness res.`1.`1 i) = l'
            /\ size (nth witness res.`2.`1 i) = l'
            /\ (forall j, 0 <= j < l' =>
                  nth witness (nth witness res.`1.`1 i) j
                  = pkfors_of (nth witness (nth witness res.`2.`1 i) j) psi
                      (set_kpidx (set_tidx (set_typeidx adi trhftype) i) j)))].
proof.
proc.
wp.
while (   ps = psi /\ ad = adi
       /\ size skFORSs = size pkFORSs
       /\ 0 <= size skFORSs <= nr_trees 0
       /\ (forall i, 0 <= i < size skFORSs =>
             size (nth witness skFORSs i) = l'
          /\ size (nth witness pkFORSs i) = l'
          /\ (forall j, 0 <= j < l' =>
                nth witness (nth witness pkFORSs i) j
                = pkfors_of (nth witness (nth witness skFORSs i) j) psi
                    (set_kpidx (set_tidx (set_typeidx adi trhftype) i) j)))).
+ wp.
  while (   ps = psi /\ ad = adi
         /\ size skFORSl = size pkFORSl
         /\ 0 <= size skFORSl <= l'
         /\ size skFORSs = size pkFORSs
         /\ (forall j, 0 <= j < size skFORSl =>
               nth witness pkFORSl j
               = pkfors_of (nth witness skFORSl j) psi
                   (set_kpidx (set_tidx (set_typeidx adi trhftype) (size skFORSs)) j))
         /\ (forall i, 0 <= i < size skFORSs =>
               size (nth witness skFORSs i) = l'
            /\ size (nth witness pkFORSs i) = l'
            /\ (forall j, 0 <= j < l' =>
                  nth witness (nth witness pkFORSs i) j
                  = pkfors_of (nth witness (nth witness skFORSs i) j) psi
                      (set_kpidx (set_tidx (set_typeidx adi trhftype) i) j)))).
  - seq 1 : (#pre).
    + by call (: true ==> true).
    exists* skFORS, ps, (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSs)) (size skFORSl));
    elim* => sk0 ps0 ad0.
    wp; call (genpkfors_cf_h sk0 ps0 ad0).
    skip => /> &hr hsz h0 hle hszs hinv hinvs hlt.
    split; first by rewrite !size_rcons hsz.
    split; first by rewrite size_rcons; split => [|_]; [apply addr_ge0 | rewrite -ltzE].
    move=> j hj0; rewrite size_rcons ltzS => hj1; rewrite !nth_rcons -hsz.
    case (j < size skFORSl{hr}) => hjl /=; first by apply hinv; rewrite hj0 hjl.
    have -> : j = size skFORSl{hr} by rewrite eqz_leq hj1 lerNgt hjl.
    by rewrite /= /pkfors_of.
  by auto => />; smt(ge2_lp size_rcons nth_rcons size_ge0).
by auto => />; smt(size_ge0 ge2_lp size_rcons nth_rcons IntOrder.expr_gt0).
qed.

(* --- A: after GprocKg.keygen, the pk pool is F of the sk pool, pointwise.
       Easier than B: the sk cube is COMPLETE before the pk nest starts, so the
       pk invariant reads sk by nth rather than tracking it. --- *)
lemma Gproc_keygen_pk_from_sk (psi : pseed) (adi : adrs) :
  hoare[GprocKg.keygen :
        ps = psi /\ ad = adi
        ==> size res.`1 = nr_trees 0
         /\ (forall i, 0 <= i < nr_trees 0 =>
               size (nth witness res.`1 i) = l'
            /\ (forall j, 0 <= j < l' =>
                  nth witness (nth witness res.`1 i) j
                  = pkfors_of (nth witness (nth witness res.`2 i) j) psi
                      (set_kpidx (set_tidx (set_typeidx adi trhftype) i) j)))].
proof.
proc.
while (   ps = psi /\ ad = adi
       /\ 0 <= size pkFORSnt <= nr_trees 0
       /\ (forall i, 0 <= i < size pkFORSnt =>
             size (nth witness pkFORSnt i) = l'
          /\ (forall j, 0 <= j < l' =>
                nth witness (nth witness pkFORSnt i) j
                = pkfors_of (nth witness (nth witness skFORSnt i) j) psi
                    (set_kpidx (set_tidx (set_typeidx adi trhftype) i) j)))).
+ wp.
  while (   ps = psi /\ ad = adi
         /\ 0 <= size pkFORSlp <= l'
         /\ 0 <= size pkFORSnt < nr_trees 0
         /\ (forall j, 0 <= j < size pkFORSlp =>
               nth witness pkFORSlp j
               = pkfors_of (nth witness (nth witness skFORSnt (size pkFORSnt)) j) psi
                   (set_kpidx (set_tidx (set_typeidx adi trhftype) (size pkFORSnt)) j))
         /\ (forall i, 0 <= i < size pkFORSnt =>
               size (nth witness pkFORSnt i) = l'
            /\ (forall j, 0 <= j < l' =>
                  nth witness (nth witness pkFORSnt i) j
                  = pkfors_of (nth witness (nth witness skFORSnt i) j) psi
                      (set_kpidx (set_tidx (set_typeidx adi trhftype) i) j)))).
  - sp 1.
    exists* skFORS, ps, (set_kpidx (set_tidx (set_typeidx ad trhftype) (size pkFORSnt)) (size pkFORSlp));
    elim* => sk0 ps0 ad0.
    wp; call (genpkfors_cf_h sk0 ps0 ad0).
    skip => /> &hr h0 hle h0nt hnt hinv hinvs hlt.
    split; first by rewrite size_rcons; split => [|_]; [apply addr_ge0 | rewrite -ltzE].
    move=> j hj0; rewrite size_rcons ltzS => hj1; rewrite nth_rcons.
    case (j < size pkFORSlp{hr}) => hjl /=; first by apply hinv; rewrite hj0 hjl.
    have -> : j = size pkFORSlp{hr} by rewrite eqz_leq hj1 lerNgt hjl.
    by rewrite /= /pkfors_of.
  by auto => />; smt(ge2_lp size_rcons nth_rcons size_ge0).
(* the sk cube nest: nothing to establish but ps/ad, four levels deep *)
wp.
while (ps = psi /\ ad = adi).
+ wp.
  while (ps = psi /\ ad = adi).
  - wp.
    while (ps = psi /\ ad = adi).
    * wp.
      while (ps = psi /\ ad = adi).
      + by auto.
      by auto.
    by auto.
  by auto.
by auto => />; smt(size_ge0 ge2_lp IntOrder.expr_gt0).

qed.

(* --- 2b: THE FISSION.  sk pools agree (brick 2a), and each side's pk pool is
       the same pointwise function of its sk pool (A and B), so the pk pools
       agree.  This is the `conseq <equiv> <hoare> <hoare>` shape used in-tree at
       RtopCSoundness.ec:586. --- *)
(* The pure half of the fission, with no program logic: two pk pools that are
   the SAME pointwise function of the SAME sk pool are equal. *)
lemma pk_pools_eq (pkL pkR : FTWES.pkFORS list list) (skL : FTWES.skFORS list list)
                  (psi : pseed) (adi : adrs) :
     size pkL = nr_trees 0
  => size pkR = nr_trees 0
  => (forall i, 0 <= i < nr_trees 0 =>
        size (nth witness pkL i) = l'
     /\ forall j, 0 <= j < l' =>
          nth witness (nth witness pkL i) j
          = pkfors_of (nth witness (nth witness skL i) j) psi
              (set_kpidx (set_tidx (set_typeidx adi trhftype) i) j))
  => (forall i, 0 <= i < nr_trees 0 =>
        size (nth witness pkR i) = l'
     /\ forall j, 0 <= j < l' =>
          nth witness (nth witness pkR i) j
          = pkfors_of (nth witness (nth witness skL i) j) psi
              (set_kpidx (set_tidx (set_typeidx adi trhftype) i) j))
  => pkL = pkR.
proof.
  move=> hszL hszR hL hR.
  apply (eq_from_nth witness); 1: by rewrite hszL hszR.
  move=> i hi.
  have hi' : 0 <= i < nr_trees 0 by smt().
  have [hsL hvL] := hL i hi'.
  have [hsR hvR] := hR i hi'.
  apply (eq_from_nth witness); 1: by rewrite hsL hsR.
  move=> j hj.
  have hj' : 0 <= j < l' by smt().
  by rewrite (hvL j hj') (hvR j hj').
qed.



(* ==========================================================================
   TIER 1, BRICK 2b COMPLETE (2026-08-04) — THE LOOP FISSION, PROVED.

   `GprocKg.keygen` samples the whole FORS secret-key cube and then computes the
   public pool in a second pass; `FTWES.M_FORS_ES_NPRF.keygen` interleaves them.
   Both halves now agree: the secret cubes by brick 2a (GprocKg_sk_eq) and the
   public pools because each is the SAME pointwise function of its secret pool
   (Gproc_keygen_pk_from_sk / MM45_keygen_pk_from_sk), combined by the pure
   list-reasoning helper pk_pools_eq.

   WHAT IT COST, recorded because the shape of the difficulty was not where I
   predicted it.  I called this "the wall" and said it needed `gen_pkFORS`
   characterised as a function; that characterisation already existed
   (genpkfors_cf_h, RtopCSoundness.ec:875) in a file this one imports.  The
   actual difficulty was mundane: `conseq` leaves FIVE subgoals, the PRE goal
   comes before the POST goal, and four failed attempts were all addressing the
   pre goal with an intro pattern written for the post goal -- diagnosed only
   after dumping every subgoal instead of the last one.  The final mismatch was
   a shape difference: MM45's characterisation carries THREE conjuncts (pk size,
   sk size, pointwise value) where the helper's premise takes two.

   WHAT IT DOES NOT DO: it bounds nothing.  This is the keygen correspondence
   the Q reduction will need, not the reduction.  Q remains unbounded, and the
   signing sites this would eventually have to meet are still INERT
   (XmssmtCC_All.ec:9539-9541).
   ========================================================================== *)

lemma GprocKg_keygen_eq (psi : pseed) (adi : adrs) :
  equiv[GprocKg.keygen ~ FTWES.M_FORS_ES_NPRF.keygen :
        ={ps, ad} /\ ps{1} = psi /\ ad{1} = adi
        ==> res{1}.`2 = res{2}.`2.`1 /\ res{1}.`1 = res{2}.`1.`1].
proof.
  conseq GprocKg_sk_eq
         (Gproc_keygen_pk_from_sk psi adi)
         (MM45_keygen_pk_from_sk psi adi).
+ smt().
move=> &1 &2 hpre rL rR [hsk [[hszL hL] [hszR1 [hszR2 hR]]]].
split; 1: by apply hsk.
apply (pk_pools_eq rL.`1 rR.`1.`1 rL.`2 psi adi) => //.
move=> i hi; rewrite hsk.
have [h1 [h2 h3]] := hR i hi.
by split.
qed.


(* ===========================================================================
   OPTION (a) -- THE INSTRUMENTED THREE-FLAG GPROC GAME AND ITS SPLIT.
   Added 2026-08-04 (run 24).

   WHY THIS SHAPE.  The three keygen bricks above (Gproc_uncovered_gives_witness,
   GprocKg_sk_eq, GprocKg_keygen_eq) are true, admit-free, gate-certified -- and
   have no consumer anywhere outside this file.  The lesson taken here is to ship
   the CONSUMER in the same commit as the artifact, which is why gproc_V_split
   sits directly below the game it splits.

   CORRECTION, 2026-08-04 (run 25) -- THE SENTENCE THAT USED TO BE HERE WAS
   HALF WRONG, AND IT IS WORTH SAYING WHICH HALF.  It read: the bricks are
   "INERT: grep shows zero consumers anywhere outside this file, and MM45's
   bounding cascade contains no keygen~keygen step at all, so the correspondence
   they establish is not a step the template ever takes."
   The grep fact is true and the first clause about the CASCADE is true -- the
   mu_split algebra in EUFCMA_MFORSTWESNPRF_OPRE really does not relate keygens.
   THE INFERENCE IS FALSE.  Every individual BRANCH REDUCTION opens with exactly
   such a correspondence in its simulation invariant.  MM45's TRCO branch, at
   base-c10-split/FORS_ES.ec:5951-5952, carries

       /\ skFORSs{1} = R_TRCOSMDTTCRC_EUFCMA.skFORSs{2}
       /\ pkFORSs{1} = R_TRCOSMDTTCRC_EUFCMA.pkFORSs{2}

   and the TRH branch (:4840-4841) carries the same two lines, because each
   reduction's pick() REBUILDS the key pool through the collection oracle and the
   proof must tie the rebuilt pool to the honest one.  That invariant then
   characterises the pk pool as
       trco pp (set_kpidx (set_typeidx adt trcotype) (get_kpidx adt))
                (flatten (map DigestBlock.val rsk))
   with rsk = mkseq (fun u => val_bt_trh pp adt (list2tree lfst) u) k -- which is
   `pkfors_of` above, structurally identical.
   So the bricks are UNCONSUMED, not off the critical path; "no consumer yet" and
   "not needed" are different claims and I asserted the second from the first.

   WHAT THIS BUYS, STATED FLATLY: NOTHING NUMERIC.  gproc_Q_decomposition is an
   EXACT EQUALITY, and the decomposition step is pure probability algebra that
   would hold for ANY two flags -- including constant ones.  All of its content
   is in the flag DEFINITIONS being MM45's (FORS_ES.ec:3216-3242), which is what
   makes each of the three terms a target for MM45's three reductions.  With all
   three terms unreduced, Q = T1 + T2 + T3 is still compatible with Q = 1, so
   this does NOT bound Q and the headline capstone bound is unchanged.
   What it does is turn one opaque term into three whose reduction templates are
   known and already written down in the base.
   =========================================================================== *)
(* ---------------------------------------------------------------------------
   EUF_CMA_Gproc_V -- EUF_CMA_Gproc_I plus MM45's two extra ghost break
   classifiers, ported from base-c10-split/FORS_ES.ec:3196-3243.

   `covered` here IS MM45's valid_ITSR half (C10 states it as an `all`, MM45 as
   a `forall ... => ... \in`; same predicate).  The two additions are:

     valid_OpenPRE  <- leaf' = leaf     (forged leaf equals honest leaf)
     valid_TRHTCR   <- root' = root     (forged root equals honest root)

   The selector is MM45's, and it is the COMPUTABLE form of brick 1's
   existential: `find` on the first index-triple of the forgery's hC that is not
   in the recorded coverage.  Under !covered such an element exists, so `find`
   lands in range -- which is what makes the ghost block total.
   --------------------------------------------------------------------------- *)
module EUF_CMA_Gproc_V (A : Adv_EUFCMA_Gproc) = {
  var covered : bool
  var valid_OpenPRE : bool
  var valid_TRHTCR : bool

  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pkFORSnt : FTWES.pkFORS list list;
    var skFORSnt : FTWES.skFORS list list;
    var m' : msg;
    var sig' : sigGproc;
    var mk' : mkey;
    var sigFORSTW' : FTWES.sigFORSTW;
    var cm : FTWES.msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var pkFORS' : FTWES.pkFORS;
    var is_valid, is_fresh : bool;
    (* ghost *)
    var lidxs', cov : (int * int * int) list;
    var dfidx, dftidx, dflfidx : int;
    var tidx2, kpidx2 : int;
    var x' : dgstblock;
    var ap' : FTWES.apFORSTW;
    var skF : FTWES.skFORS;
    var adT : adrs;
    var leaf', leaf, root', root : dgstblock;

    ad <- adz;
    ps <$ dpseed;
    (pkFORSnt, skFORSnt) <@ GprocKg.keygen(ps, ad);

    O_CMA_Gproc_I.init(skFORSnt, ps, ad);
    (m', sig') <@ A(O_CMA_Gproc_I).forge((pkFORSnt, ps, ad));

    (mk', sigFORSTW') <- sig';
    (cm, idx) <- FTWES.mco mk' m';
    (tidx, kpidx) <- edivz (Index.val idx) l';

    pkFORS' <@ FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW(sigFORSTW', cm, ps,
                 set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

    is_valid <- M.F.predC_fors (FTWES.mco mk' m')
                /\ pkFORS' = nth witness (nth witness pkFORSnt tidx) kpidx;
    is_fresh <@ O_CMA_Gproc_I.fresh(m');

    covered <-
      all (fun x => x \in flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2)
                                       O_CMA_Gproc_I.ts))
          (M.F.hC sig'.`1 m');

    (* ---- ghost instrumentation (MM45 FORS_ES.ec:3216-3242) ---------------- *)
    lidxs' <- M.F.hC mk' m';
    cov    <- flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2)
                           O_CMA_Gproc_I.ts);
    (dfidx, dftidx, dflfidx) <-
      nth witness lidxs' (find (fun i => ! (i \in cov)) lidxs');
    (x', ap') <- nth witness (FTWES.DBAPKL.val sigFORSTW') dftidx;
    (tidx2, kpidx2) <- edivz dfidx l';
    skF <- nth witness (nth witness skFORSnt tidx2) kpidx2;
    adT <- set_kpidx (set_tidx (set_typeidx ad trhftype) tidx2) kpidx2;
    leaf' <- f ps (set_thtbidx adT 0 (dftidx * t + dflfidx)) (DigestBlock.val x');
    leaf  <- nth witness (fors_leaves_op_cube skF ps adT dftidx) dflfidx;
    valid_OpenPRE <- leaf' = leaf;
    root' <- FTWES.val_ap_trh ps adT ap' dflfidx leaf' dftidx;
    root  <- FTWES.val_bt_trh ps adT
               (list2tree (fors_leaves_op_cube skF ps adT dftidx)) dftidx;
    valid_TRHTCR <- root' = root;

    return is_valid /\ is_fresh;
  }
}.

(* The instrumentation is ghost: it reads only already-computed values and
   writes only fresh variables, so it moves neither `res` nor `covered`. *)
lemma gproc_V_eq
  (A <: Adv_EUFCMA_Gproc{-O_CMA_Gproc_I, -EUF_CMA_Gproc_I, -EUF_CMA_Gproc_V}) &m :
    Pr[EUF_CMA_Gproc_I(A).main() @ &m : res /\ ! EUF_CMA_Gproc_I.covered]
  = Pr[EUF_CMA_Gproc_V(A).main() @ &m : res /\ ! EUF_CMA_Gproc_V.covered].
proof.
byequiv (_ : ={glob A} ==>
             res{1} = res{2}
          /\ EUF_CMA_Gproc_I.covered{1} = EUF_CMA_Gproc_V.covered{2}) => //.
proc.
wp.
(* `sim` cannot decompose the post as displayed: it is an EQUALITY OF TWO `all`
   APPLICATIONS, not a conjunction of `={...}`.  Strengthen to the ={...} form
   it can drive; the ghost block has already been absorbed by `wp` and leaves
   only dead `let` bindings, so nothing about it survives into this goal. *)
conseq (_ : ={glob A}
        ==> ={is_valid, is_fresh, sig', m'} /\ ={glob O_CMA_Gproc_I}).
+ by move=> />.
sim.
qed.

(* ---------------------------------------------------------------------------
   THE CONSUMER.  An instrumented game nobody splits on is dead weight -- that
   is exactly what happened to the three keygen bricks, which have no consumer
   anywhere in the closure.  So the split lands in the same file as the game.

   This is MM45's first hop (FORS_ES.ec:3849, `rewrite Pr[mu_split ...]`),
   ported: an EXACT partition of Q over the two new flags.  Equality, not <=;
   no slack anywhere.
   --------------------------------------------------------------------------- *)
lemma gproc_V_split
  (A <: Adv_EUFCMA_Gproc{-O_CMA_Gproc_I, -EUF_CMA_Gproc_I, -EUF_CMA_Gproc_V}) &m :
    Pr[EUF_CMA_Gproc_V(A).main() @ &m : res /\ ! EUF_CMA_Gproc_V.covered]
  =   Pr[EUF_CMA_Gproc_V(A).main() @ &m :
           (res /\ ! EUF_CMA_Gproc_V.covered) /\ EUF_CMA_Gproc_V.valid_OpenPRE]
    + Pr[EUF_CMA_Gproc_V(A).main() @ &m :
           ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
           /\ EUF_CMA_Gproc_V.valid_TRHTCR]
    + Pr[EUF_CMA_Gproc_V(A).main() @ &m :
           ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
           /\ ! EUF_CMA_Gproc_V.valid_TRHTCR].
proof.
(* Each split gets its OWN `have`.  Doing both rewrites on the main goal fails:
   `rewrite Pr[mu_split X]` picks an instantiation from the first match and then
   splits EVERY occurrence of that instance -- so the second rewrite also split
   the valid_OpenPRE term on the RIGHT-hand side, leaving a 3-vs-4 term goal
   that `ring` cannot close.  Isolating each split keeps one instantiation per
   rewrite. *)
have h1 :
    Pr[EUF_CMA_Gproc_V(A).main() @ &m : res /\ ! EUF_CMA_Gproc_V.covered]
  =   Pr[EUF_CMA_Gproc_V(A).main() @ &m :
           (res /\ ! EUF_CMA_Gproc_V.covered) /\ EUF_CMA_Gproc_V.valid_OpenPRE]
    + Pr[EUF_CMA_Gproc_V(A).main() @ &m :
           (res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE].
+ by rewrite Pr[mu_split EUF_CMA_Gproc_V.valid_OpenPRE].
have h2 :
    Pr[EUF_CMA_Gproc_V(A).main() @ &m :
         (res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE]
  =   Pr[EUF_CMA_Gproc_V(A).main() @ &m :
           ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
           /\ EUF_CMA_Gproc_V.valid_TRHTCR]
    + Pr[EUF_CMA_Gproc_V(A).main() @ &m :
           ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
           /\ ! EUF_CMA_Gproc_V.valid_TRHTCR].
+ by rewrite Pr[mu_split EUF_CMA_Gproc_V.valid_TRHTCR].
by rewrite h1 h2; ring.
qed.

(* Q itself, decomposed.  Combining the two: the UNREDUCED bad-event probability
   carried by EUFCMA_SPHINCS_PLUS_C10_GROUNDED is EQUAL to three named terms. *)
lemma gproc_Q_decomposition
  (A <: Adv_EUFCMA_Gproc{-O_CMA_Gproc_I, -EUF_CMA_Gproc_I, -EUF_CMA_Gproc_V}) &m :
    Pr[EUF_CMA_Gproc_I(A).main() @ &m : res /\ ! EUF_CMA_Gproc_I.covered]
  =   Pr[EUF_CMA_Gproc_V(A).main() @ &m :
           (res /\ ! EUF_CMA_Gproc_V.covered) /\ EUF_CMA_Gproc_V.valid_OpenPRE]
    + Pr[EUF_CMA_Gproc_V(A).main() @ &m :
           ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
           /\ EUF_CMA_Gproc_V.valid_TRHTCR]
    + Pr[EUF_CMA_Gproc_V(A).main() @ &m :
           ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
           /\ ! EUF_CMA_Gproc_V.valid_TRHTCR].
proof. by rewrite (gproc_V_eq A &m) (gproc_V_split A &m). qed.
