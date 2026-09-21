(* ==========================================================================
   GprocTCollNamed.ec -- the deployed headline with the WOTS encoding-collision
   term MOVED to the +C layer.  Landed 2026-09-14.

   WHAT IT IS.  GprocWotsNamed.ec's
   `EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS_WOTSNAMED`
   names the WOTS-TW game as four terms, one of which is
       Pr[Game4_WOTSTWES_BadEnc(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))))
          : res /\ BadEncFlag.badenc].
   The theorem below is that statement with THAT term replaced by
       Pr[T_COLL_RES_ENUM(R_TCOLL(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                          O_TCollEnum_Default, FC.O_THFC_Default) : res]
   through `BadEncStep4.ec::badenc_le_tcoll`.  Proof: transitivity, nothing else.

   WHY.  The tree has recorded the raw term as a DEBT since 2026-08-13
   (scratch/FINDING-seed-withholding-is-not-the-lever.md, section 3, condition 2 --
   that file's NUMERIC claims were later retracted; condition 2 is about PLACEMENT and
   is unaffected):
     "the named-assumption term must eventually REPLACE the raw
      `Game4_WOTSTWES_BadEnc` term at the headline.  Until it does ... an
      undischarged debt".
   At the WOTS-TW layer the adversary CHOOSES the WOTS message, so it can hand over a
   colliding pair; BadEncCountermodel.ec::badenc_is_one proves that term equals 1 for an
   explicit replay adversary -- NOT this deployed instantiation, whose value there is not
   established.  At the +C layer the adversary picks the preimage (m', ctr') but not the
   digest, and a win needs a SECOND surface preimage, under `ThC ps ad`, of a codeword
   the target oracle recorded (TCollResEnum.ec::tcoll_win_needs_coll): a search, not a
   hand-over.  That is an EVENT-level fact -- it says a win requires a collision, not
   that collisions are absent or hard.  This file performs the replacement the debt
   names.

   A LOOSER INEQUALITY -- READ THIS FIRST.  `badenc_le_tcoll` is old <= new, so this
   right-hand side is pointwise LARGER than WOTSNAMED's, and F is narrower by one
   separation.  As an inequality this theorem is STRICTLY WEAKER than WOTSNAMED: it is
   a corollary of it.  Quote WOTSNAMED when you want the tighter statement.  What this
   one buys is WHICH term is carried -- a standalone, named +C game with a proved win
   characterisation, in place of an internal game probability of the WOTS-TW proof.
   Assumption-surface progress, not a number.

   THE PRICE IN THE HYPOTHESES: ONE module separation, ZERO new premises.
   `badenc_le_tcoll` needs `c <= p_tgts`, which the headline already carries.  MEASURED with
   scratch/probe_tcoll_compose.ec rather than assumed:
     * dropping `-O_TCollEnum_Default` fails the restriction check: load-bearing;
     * `-R_TCOLL`, which `badenc_le_tcoll` also lists, is NOT added because it is
       IMPLIED.  `R_TCOLL.O_wrap` declares no `var` of its own; its only state comes from
       `include var O_MEUFGCMA_WOTSC_Default`, and `include var` SHARES the included
       module's globals rather than copying them -- the base tree relies on exactly
       that (`O_Game34_WOTSTWES_AltX` appends to `qs` through `include var
       O_MEUFGCMA_WOTSTWESNPRF`, and `Game4_WOTSTWES_BadEnc` reads that module's log;
       BadEncStep4.ec:488 names it `O_MEUFGCMA_WOTSTWESNPRF.qs{1}`).  F already excludes
       `O_MEUFGCMA_WOTSC_Default`, so `-R_TCOLL` would exclude nothing more.  Measured:
       without it the composition compiles.

   IT BOUNDS NOTHING -- READ THIS BEFORE QUOTING.
     * `T_COLL_RES_ENUM` is an UNBOUNDED hardness assumption, and there is NO NUMBER to
       quote for it.  The constant-sum surface count is machine-checked -- and as of
       2026-09-21 it is IN the closure (cdrafts-split/C10SurfaceKernel.ec::c10_surface_count,
       C10Surface.ec::c10_surface_bits), promoted from experiments/wots-badenc/count.
       READ WHAT IS ACTUALLY PROVED: the exact integer 22169393903687611906220091621190388
       and the bracket 2^114 < |C_T| < 2^115.  The decimal "2^114.0941" this comment used to
       give is that integer's base-2 LOGARITHM, computed outside EasyCrypt; it appears only in
       a comment (C10Surface.ec:61) and is not a theorem.  No derivation turns a
       surface size into an advantage bound against an adversary that holds the keyed
       collection oracle and chooses its own counter.  Every figure this tree has attached
       to the term -- ~2^-72, 2^-82, 2^-78.09 -- was RETRACTED or WITHDRAWN (vendored
       README, CORRECTION 2026-08-14 (final) and CONCLUSION 2026-08-18).
     * Do NOT read the move as "the deployment keeps the WOTS message key-determined".
       That is FALSE at the verifier: the layer-0 WOTS message is built from FORS secrets
       and auth paths read out of the signature (sphincs-c10/src/hypertree.rs:386-419).
     * `T_COLL_RES_ENUM` has NO disjointness conjunct (TCollResEnum.ec, FAITHFULNESS
       NOTES): its win set is LARGER than the S-TCR(+C) template's, so the assumption is
       STRICTLY STRONGER than a THF assumption.  Sound to charge, expensive to believe.
     * Like every hardness term in this statement, it means something only for
       RESOURCE-BOUNDED adversaries, which this development does not formalise: `find`
       receives `ps` and `thfc` is an ambient op, so an unbounded adversary wins whenever
       a second surface preimage of a recorded codeword exists.  That encoder collisions
       exist AT ALL rests on a target-sum antichain count the tree states in prose and does
       not mechanise; that a GIVEN recorded codeword has a second preimage is stated
       nowhere.
     * `Pr[M.F.ITSRC10 ..]` is still carried unreduced and is still the honest headline
       blocker.

   PARALLEL, NOT AN EDIT.  GprocWotsNamed.ec's STATEMENT is untouched and stays quotable
   (one stale preamble comment in that file was corrected the same day; see its line 49).

   CONTROLS: scratch/gtn_ctl{A,B,C}.ec.  A drops `badenc_le_tcoll` from the composition
   -- the one that matters: if the theorem still went through, the substitution would
   be doing nothing.  B drops the WOTSNAMED statement.  C drops `-O_TCollEnum_Default`.
   ========================================================================== *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS XmssmtCC_All RtopCSoundness FxChain GprocFORSC10 GprocVI.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme WOTS_C_Interactive.
require FORS_C10 FORS_C10_Multi DigitalSignatures.
require import BitEncoding. import BS2Int BitChunking.
require import GFailCharged XmssmtCCCharged SphincsC10CapstoneCharged.
require import GprocT1Opre GprocT2Trh GprocT3Trco GprocQBound.
require import GprocQWired.   (* inherited preamble; this file has no WitnessF check *)
(* c10_n / c10_len / c10_k / c10_r for the DEPLOYED variant below.  Same import
   GprocQWired.ec:55 uses, and both files are ALREADY closure members, so this adds
   no new file to the cone -- verified after the edit (CONE_FILES stays 45). *)
require import C10DeployedInstance.
(* for c10_dfC_separations_from_width_alone -- the four dfC0 separations WITHOUT the
   redundant n/len/k premises.  C10DeployedCapstone is already a certified root and is
   already in the 45-file cone, so this adds no cone file. *)
require import C10DeployedCapstone.

import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.
require import GprocChargedQWired WotsLegCharged.
require import GprocWotsNamed.
require import TCollResEnum BadEncToTColl BadEncStep4.

lemma EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS_TCOLLNAMED
  (F <: Adv_EUFCMA_C{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V, -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default,
             -R_top,
             -DSSC.Stateless.O_CMA_Default, -O_CMA_SPHINCSPLUSTWC_FS,
             -SKG_PRF.O_PRF_Default, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V,
             -R_top_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV,
             -R_fors_p, -O_CMA_Gproc, -O_CMA_Gproc_I, -R_ITSRC10_Gproc,
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default,
             (* the nine Q-leg separations gproc_Q_bound needs -- identical to the
                block GprocQWired.ec carries, and a deliberate NARROWING of F. *)
             -EUF_CMA_Gproc_V, -R_OPRE_Gproc, -R_TRH_Gproc, -R_TRCO_Gproc,
             -FTWES.F_OpenPRE.O_SMDTOpenPRE_Default,
             -FTWES.TRHC_TCR.O_SMDTTCR_Default, -FTWES.TRHC.O_THFC_Default,
             -FTWES.TRCOC_TCR.O_SMDTTCR_Default, -FTWES.TRCOC.O_THFC_Default,
             (* the six WOTS-TW internals the charged leg needs -- a NARROWING *)
             -FC_UD.O_SMDTUD_Default, -FC_TCR.O_SMDTTCR_Default,
             -FC_PRE.O_SMDTPRE_Default, -R_SMDTUDC_Game23WOTSTWES,
             -R_SMDTTCRC_Game34WOTSTWES, -R_SMDTPREC_Game4WOTSTWES,
             (* the ONE separation badenc_le_tcoll adds -- a NARROWING, and
                load-bearing (scratch/gtn_ctlC.ec).  Its other new one,
                -R_TCOLL, is IMPLIED by -O_MEUFGCMA_WOTSC_Default above. *)
             -O_TCollEnum_Default })
  &m :
     (* GRIND REACHABILITY -- the "+C" grind assumption, made explicit.  See
        WotsLegCharged.ec's header for why nothing in the closure supplies it. *)
     (forall (m : msg), is_lossless (dcond dmkey (good_fors m))) =>
     (forall (O <: SOracle_CMA_C{-F}), islossless O.sign => islossless F(O).forge) =>
    c <= p_tgts =>
    (* THE THREE DEPLOYED-PARAMETER PREMISES ARE GONE (2026-08-27).  They were
       REDUNDANT and this tree already knew it: C10DeployedCapstone.ec:407 records
       "the four dfC0 separations follow from the WIDTH premise ALONE, with n, len and
       k FREE ... its name promises more than its proof uses", and proves
       `c10_dfC_separations_from_width_alone` for exactly that.  The separations are a
       MOD-8 argument -- dfC0 = 8n+33 = 1 (mod 8) while 8n, 8n*len, 8n*2, 8n*k are all
       0 (mod 8) for ANY integers -- so it never looks at 16/43/13.  When this lemma was
       written on 2026-08-24 it reached for `c10_dfC_separations_deployed` (the variant
       WITH the premises) instead; that was my miss, not a gap in the tree.
       WHAT REMAINS IS TWO PREMISES, AND THEY DIFFER IN KIND:
         * `c <= p_tgts`                     -- a PARAMETER CHOICE (the SM-DT-TCR game
           must be given at least as many targets as there are instances); the tree
           classifies it as not-a-theorem-and-not-meant-to-be (C10DeployedGeometry.ec:468).
         * `size (emb_in witness) = 8*n + c10_r` -- retained for compatibility.
           UPDATE 2026-09-21: emb_in is now the concrete compact encoder;
           c10_emb_in_width proves this binder without an extra premise. The
           earlier description as a constraint on a free op is historical. *)
    size (emb_in witness) = 8 * n + c10_r =>   (* NODE || u32 counter *)
    Pr[EUFCMA_C10(F).main() @ &m : res]
      <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
           - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
       + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(F)),
                          M.F.O_ITSRC10_Default).main() @ &m : res]
           + ( Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(F)),
                    FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
             + Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(F)),
                    FTWES.TRHC_TCR.O_SMDTTCR_Default,
                    FTWES.TRHC.O_THFC_Default).main() @ &m : res]
             + Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(F)),
                    FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                    FTWES.TRCOC.O_THFC_Default).main() @ &m : res] ) )
       + ( (* ---- the WOTS-TW game, NAMED ---- *)
             (   (w - 2)%r
                 * `|Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
                        FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(false) @ &m : res]
                     - Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
                        FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(true) @ &m : res]|
               + Pr[FC_TCR.SM_DT_TCR_C(R_SMDTTCRC_Game34WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
                        FC_TCR.O_SMDTTCR_Default, FC.O_THFC_Default).main() @ &m : res]
               + ( Pr[FC_PRE.SM_DT_PRE_C(R_SMDTPREC_Game4WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
                        FC_PRE.O_SMDTPRE_Default, FC.O_THFC_Default).main() @ &m : res]
                 (* ---- encoding collision, MOVED to the +C layer (was Game4_WOTSTWES_BadEnc) ---- *)
                 + Pr[T_COLL_RES_ENUM(R_TCOLL(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                        O_TCollEnum_Default, FC.O_THFC_Default).main() @ &m : res] ) )
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res]
           + Pr[GAME1_INT(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)),
                          O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
                  res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps
                                  O_MEUFGCMA_WOTSC_Default.qs] ).
proof.
move=> hgrind Fll hc hsz.
have h1 := EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS_WOTSNAMED F &m hgrind Fll hc hsz.
have h2 := badenc_le_tcoll (R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))) &m hc.
smt().
qed.
