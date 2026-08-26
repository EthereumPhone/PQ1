(* ==========================================================================
   C10DeployedGeometry.ec — THE DEPLOYED-GEOMETRY RECEIPT.

   WHAT WAS ASKED FOR, AND WHAT THIS IS.
   The adversarial review of 2026-07-30 recommended a "deployed-instantiation
   corollary" pinning the real encoder, target 205, parameters, the 32-bit
   counter and serialization, replacing universal N2 with a grind-failure
   probability, and replacing `mkg_adv` / `mtree_*` with named advantages.

   THIS FILE DELIVERS A STRICT SUBSET, and says so up front:

     DONE   (1) ADMISSIBILITY of the deployed C10 parameter values against every
                constraint the model declares for them.
     DONE   (2) The WIDTH OBSTRUCTION that blocks pinning the encoder, stated as
                a CHECKED FACT against the model's own types instead of prose in
                an unwired leaf.
     NOT DONE  the encoder / target 205 / counter / serialization pinning, the
                N2 -> grind-failure-probability replacement, and the free-real
                replacement.

   (2) IS THE REASON (1) IS AS FAR AS IT GOES.  NARROWED 2026-07-30 (second
   review wave; the first narrowing missed this paragraph and the one at the
   `c10_codomain_exceeds_domain_model` lemma).  What is MECHANIZED here is a
   CARDINALITY GAP: at deployed geometry the codeword space (w^len = 2^129) is
   strictly larger than the message space (2^(8n) = 2^128).  The step from that
   to "the encoder cannot be pinned" is PROSE -- it needs the finite-type
   cardinality argument carried to `msgWOTS`/`emsgWOTS`, which is NOT done in
   this file, plus the faithfulness argument about the deployed 129-bit digit
   window.  Do not cite this file as a mechanized impossibility theorem.

   WHY THIS FILE REQUIRES THE MODEL, AND WHERE THE SURROGATE LINE FALLS.
   `experiments/tcollres-leg/Identification.ec` records the trap: everything there
   is proved about a type-DISCONNECTED surrogate (its own `wd`, its own `int list`
   codewords), so "EasyCrypt has verified NOTHING there about `encode_msgWOTS`",
   and the correspondences were hand transcriptions.

   SO BE PRECISE ABOUT THIS FILE (corrected during review of my own first draft,
   whose header claimed more than it delivered):
     * Section 1's `c10_admissible_*` and section 2's `c10_*_space` lemmas are
       PURE INTEGER ARITHMETIC about the `c10_*` ops defined below.  They are
       exactly the side conditions a clone at deployed values would have to
       discharge -- useful, but on their own they say nothing about the model.
     * The `*_model` lemmas at the end are the ONES THAT TIE: they are stated
       over the MODEL's own `n`, `w`, `len` under hypotheses fixing them to the
       deployed values, so EasyCrypt checks the connection rather than a reader.
   Cite the `_model` forms when the claim is about the model.
   ========================================================================== *)
require import AllCore List IntDiv Ring StdOrder.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme.
require import WOTS_C_Interactive.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
(* for the `emsgWOTS` codeword type + `digitsum`, used in section 5 *)
import EmsgWOTS.
import WOTS_C_Real.
import WOTS_C_Interactive.
import IntOrder.

(* ==========================================================================
   0.  THE DEPLOYED C10 GEOMETRY (docs/CLAUDE.md: h=18, d=2, a=11, k=13, w=8,
       n=16, len=43, target_sum=205, sig=4008 B).
   These are PLAIN INTEGERS.  They are not wired into the model -- they are the
   values the hypotheses below fix the model's parameters to.
   ========================================================================== *)
op c10_n        : int = 16.
op c10_log2_w   : int = 3.
op c10_w        : int = 8.
op c10_len      : int = 43.
op c10_target_sum : int = 205.

(* ==========================================================================
   1.  ADMISSIBILITY.  Every constraint the model DECLARES on these parameters
       is satisfied by the deployed values.

       This is the honest core of "pins the deployed parameters": it is an
       ADMISSIBILITY receipt, NOT an instantiation.  It does not clone the theory
       at these values; it checks that doing so could not fail on the parameter
       side.  Read the name literally.

       It has teeth: had C10's geometry violated any declared bound, the
       corresponding lemma below would be unprovable.  `val_log2w` is the one
       that historically DID bite -- MM45's original three-literal restriction
       made log2_w = 3 inexpressible, which is why WOTS_TW_ES.ec:31 records a
       deliberate relaxation to `2 <= log2_w`.
   ========================================================================== *)
lemma c10_admissible_n        : 1 <= c10_n.       proof. by rewrite /c10_n. qed.
lemma c10_admissible_log2w    : 2 <= c10_log2_w.  proof. by rewrite /c10_log2_w. qed.
lemma c10_admissible_len      : 2 <= c10_len.     proof. by rewrite /c10_len. qed.

(* `w` is DERIVED in the model (`const w = 2 ^ log2_w`), so the deployed pair
   must be mutually consistent -- an independent check, not a restatement. *)
(* `8 = 2 ^ 3`, proof shape reused verbatim from
   experiments/tcollres-leg/EncoderBridge.ec:120 (where it is already checked). *)
lemma c10_pow8 : 8 = 2 ^ 3.
proof. by rewrite (_ : 3 = 2 + 1) 1:// exprS 1:// (_ : 2 = 1 + 1) 1:// exprS 1:// expr1. qed.

lemma c10_w_consistent : c10_w = 2 ^ c10_log2_w.
proof. by rewrite /c10_w /c10_log2_w c10_pow8. qed.

(* The gate value is attainable as a digit sum at this geometry: 43 digits, each
   in [0,7], sum at most 301; 205 <= 301, and 205 >= 0.  So `target_sum = 205` is
   not out of range for the deployed codeword space.  (Attainability of exactly
   205 by the deployed encoder is a different claim and is NOT made here.) *)
lemma c10_target_sum_in_range :
  0 <= c10_target_sum <= c10_len * (c10_w - 1).
proof. by rewrite /c10_target_sum /c10_len /c10_w. qed.

(* ==========================================================================
   2.  THE WIDTH OBSTRUCTION — why the encoder cannot be pinned here.

   The model fixes, by construction:
     * `msgWOTS = dgstblock` and `dgstblock` is `bool list` with `size = 8 * n`
       (WOTS_TW_ES.ec:163, :213).  The encoder's DOMAIN has 2^(8*n) elements.
     * `emsgWOTS` is `Word` over `baseW = {0..w-1}` of length `len`
       (WOTS_TW_ES.ec:219).  The encoder's CODOMAIN has w^len elements.

   At the deployed geometry that is 2^128 vs 8^43 = 2^129: the codomain is
   STRICTLY LARGER than the domain, by exactly one bit.

   WHAT THIS DOES AND DOES NOT ESTABLISH (narrowed 2026-07-30 after review).
   The cardinality gap excludes COVERING the deployed codeword space from the
   model's message type; it does NOT by itself exclude defining `encode_msgWOTS`
   as some non-surjective map.  The stronger "cannot be pinned" reading rests on
   the FAITHFULNESS argument below, which is prose, not mechanized:

   Deployed C10 signing discards the digest and
   uses only the digits (`sphincs-c10/src/wots.rs:119`), so the security-relevant
   object is the 43-digit / 129-bit window.  A `dgstblock` cannot carry it: digest
   widths in this model are multiples of 8, and 129 is not one.  Widening does not
   help either -- n = 17 gives 136 bits, and 2^136 > 8^43 leaves 2^7 preimages per
   codeword.  (That last step is NOT mechanized here; it is flagged as unmechanized
   in experiments/tcollres-leg/ThCWidth.ec too, and nothing below leans on it.)

   Retyping anyway is a fork of MM45: ~531 `ThC` mentions across 35 files plus the
   `STCRC_WC` clone binding `out_t <- dgstblock`.

   [RETRACTED 2026-07-31.  The "RESOLVED ... it is the intermediate WIDTH"
    answer recorded here on 2026-07-30 was WRONG, and so was the banked
    reviewer's cardinality diagnosis it replaced.  Both are artifacts of the
    same thing.  See section 7 at the end of this file for the reconciled
    position, established by a two-model review wave (2026-07-31) whose
    load-bearing citations were re-verified at source.  Kept for the record.]
   OPEN QUESTION, BANKED 2026-07-30 (second review wave, NOT resolved here).
   One reviewer argues the cardinality gap is the WRONG diagnosis: since
   `encode_msgWOTS` is axiom-free and the deployed digit map is itself a
   NON-surjective map of exactly this type shape, a type-correct pinning exists
   set-theoretically, and "the genuine blocker is the `two_encodings`/antichain
   structure, not cardinality."  That is plausible and would relocate this file's
   central framing -- note the fork RELATIVIZED `two_encodings` to the
   constant-sum surface precisely so the digit map could live there, which cuts
   against cardinality being the obstruction at all.
   It is recorded rather than acted on because settling it means re-deriving what
   blocks the pinning, which is its own investigation.  Nothing ABOVE depends on
   the resolution: the mechanized content of this file is the cardinality gap and
   the admissibility receipt, both of which stand either way.

   STALE VERDICT CORRECTED.  ThCWidth.ec concluded that NEITHER width reading was
   licensed because "`predC` carries NO AXIOM ANYWHERE IN THE CLOSURE, so
   `predC := fun _ => false` is a model".  That disqualifier NO LONGER HOLDS:
   `cdrafts-fork/WOTS_C_Real.ec:239` now DEFINES `predC = P`, and `P_inhabited`
   rules out the all-false model.  The ingredient that file named as missing has
   since been supplied.  The width obstruction below is independent of it and
   survives regardless.
   ========================================================================== *)

(* 8^43 = 2^129, mechanized rather than asserted. *)
lemma c10_codeword_space : c10_w ^ c10_len = 2 ^ 129.
proof.
rewrite /c10_w /c10_len c10_pow8 -exprM.
by congr.
qed.

(* The digest space at the deployed width. *)
lemma c10_message_space : 2 ^ (8 * c10_n) = 2 ^ 128.
proof. by rewrite /c10_n. qed.

(* THE OBSTRUCTION, in one line: the codomain is strictly bigger. *)
lemma c10_codomain_exceeds_domain :
  2 ^ (8 * c10_n) < c10_w ^ c10_len.
proof.
rewrite c10_codeword_space c10_message_space.
have -> : 129 = 128 + 1 by ring.
rewrite exprS 1://.
smt(expr_gt0).
qed.

(* RENAMED AND RE-SCOPED 2026-07-30 (adversarial review, CONFIRMED against source).
   This lemma was called `c10_encoder_cannot_be_surjective`.  THAT NAME WAS A LIE
   ABOUT ITS OWN STATEMENT: the statement is a bare integer inequality -- it
   mentions neither `encode_msgWOTS`, nor surjectivity, nor the message/codeword
   types -- and its proof is `exact c10_codomain_exceeds_domain`, i.e. it was an
   alias.  A reader grepping for the name would have taken a cardinality fact for
   a theorem about the encoder.

   WHAT THE ARITHMETIC DOES EXCLUDE: any SURJECTION from the 2^128 messages onto
   all 2^129 codewords, since the codomain is strictly larger (and hence any
   bijection, a bijection being in particular a surjection).
   [Phrasing corrected 2026-07-30, second review wave: this read "any BIJECTION
   (equivalently, any surjection)".  Both classes are empty HERE, so the
   conclusion was unaffected, but surjection and bijection are NOT equivalent in
   general and the parenthetical asserted that they are.  In a file whose whole
   purpose is claim hygiene, loose phrasing is the defect.]
   WHAT IT DOES *NOT* EXCLUDE: defining `encode_msgWOTS` as some particular
   NON-surjective map -- including a restriction of the deployed digit map.  So
   it does not by itself prove "the encoder cannot be pinned"; it proves the
   deployed 43-digit codeword space cannot be covered from a 128-bit message
   type.  Making the impossibility claim precise would need the cardinality
   argument carried to the model's finite types, which is NOT done here. *)
lemma c10_codeword_space_not_covered :
  2 ^ (8 * c10_n) < c10_w ^ c10_len.
proof. exact c10_codomain_exceeds_domain. qed.

(* And the width fact that kills the retype-to-fit escape: 129 is not 8*k. *)
lemma c10_width_129_not_8n : ! (exists (k : int), 8 * k = 129).
proof. by apply/negP => -[k] h; smt(). qed.

(* ==========================================================================
   3.  THE TIE.  Everything above is arithmetic about `c10_*`; these are the
       statements over the MODEL's OWN parameters, so the correspondence is
       machine-checked instead of hand-transcribed.
   ========================================================================== *)

(* Deployed digest width, at the model's `n`. *)
lemma c10_digest_width_model : n = c10_n => 8 * n = 128.
proof. by move=> ->; rewrite /c10_n. qed.

(* Deployed codeword-space size, at the model's `w` and `len`. *)
lemma c10_codeword_space_model : w = c10_w => len = c10_len => w ^ len = 2 ^ 129.
proof. by move=> -> ->; exact c10_codeword_space. qed.

(* THE CARDINALITY GAP, over the model's own parameters: at deployed geometry the
   codeword space is strictly larger than the message space.

   WHAT FOLLOWS, AND ITS STATUS.  "`encode_msgWOTS` is therefore not surjective"
   is TRUE -- no map from a 2^128 set onto a 2^129 set is -- but it is NOT
   MECHANIZED HERE.  The lemma below is an inequality between two INTEGERS; it
   does not mention `encode_msgWOTS`, and nothing in this file establishes that
   `msgWOTS` and `emsgWOTS` have those cardinalities.  Bridging that needs the
   finite-type argument (DigestBlockFT / the EmsgWOTS Word clone), which is left
   undone.  Treat the non-surjectivity sentence as a PROSE CONSEQUENCE with a
   named gap, not as something the adjacent lemma proves. *)
lemma c10_codomain_exceeds_domain_model :
  n = c10_n => w = c10_w => len = c10_len => 2 ^ (8 * n) < w ^ len.
proof.
move=> hn hw hl; rewrite (c10_digest_width_model hn) (c10_codeword_space_model hw hl).
have -> : 129 = 128 + 1 by ring.
rewrite exprS 1://.
smt(expr_gt0).
qed.

(* ==========================================================================
   4.  TIE CHECK — proof that section 3 really is about the MODEL's parameters.

   A `_model` lemma that silently resolved `n` / `w` / `len` to something other
   than the model's constants would still COMPILE and would mean nothing.  That
   is the exact failure mode this file exists to avoid, so it is tested rather
   than asserted: each lemma below discharges a deployed bound BY APPLYING THE
   MODEL'S OWN DECLARED CONSTRAINT to the model's constant.  If `n` here were a
   local op, `ge1_n` would not apply to it and these would not typecheck.
   ========================================================================== *)
lemma c10_tie_n   : n = c10_n => 1 <= c10_n.
proof. by move=> <-; exact ge1_n. qed.

lemma c10_tie_len : len = c10_len => 2 <= c10_len.
proof. by move=> <-; exact ge2_len. qed.

(* `w` is DEFINED as `2 ^ log2_w` (WOTS_TW_ES.ec:37), so the model constrains it
   via the derived bound `val_w : 4 <= w` rather than an axiom.  Applying that to
   the model's `w` is the tie; 4 <= 8 holds at deployed geometry. *)
lemma c10_tie_w   : w = c10_w => 4 <= c10_w.
proof. by move=> <-; exact val_w. qed.

(* And the definitional consistency, over the model's own two constants. *)
lemma c10_tie_w_def : log2_w = c10_log2_w => w = c10_w.
proof. by move=> h; rewrite /w h /c10_log2_w /c10_w c10_pow8. qed.

(* ==========================================================================
   5.  SETTLING "ANTICHAIN vs CARDINALITY" (raised in review wave 2, banked
       above as an open question; RESOLVED here).

   THE CLAIM UNDER TEST: "the genuine blocker [to pinning `encode_msgWOTS` to
   the deployed digit map] is the `two_encodings`/antichain structure, not
   cardinality."

   ANSWER: IT DEPENDS ON THE TREE, and for THIS tree the claim is FALSE.

     base-c10          `axiom two_encodings` (WOTS_TW_ES.ec:579), UNRELATIVIZED
                       and quantified over all message pairs.  It constrains the
                       encoder directly, and identifying `encode_msgWOTS` with
                       the base-wd digit map CONTRADICTS it -- which is exactly
                       what cdrafts/LeafWiring.ec proves.  There, the antichain
                       IS the blocker.

     base-c10-fork     `lemma two_encodings` (WOTS_TW_ES.ec:665), whose entire
                       proof is `rewrite /P; apply constsum_antichain`.
                       `constsum_antichain` is a statement about arbitrary
                       CODEWORDS of equal digit sum -- it never mentions
                       `encode_msgWOTS`.  So in the fork the antichain constrains
                       the encoder NOT AT ALL, and cannot be what blocks pinning.

   Mechanized below rather than argued: the antichain property holds for an
   ARBITRARY encoder `E` on any constant-sum surface.  Since it holds for every
   E, no choice of E can violate it, so it rules out no candidate encoder.

   SO WHAT IS THE BLOCKER IN THE FORK?  Neither of the two candidates:
     * NOT the antichain -- see the lemma below.
     * NOT cardinality -- the gap forbids SURJECTIONS onto the 2^129 codeword
       space (section 2); it does not forbid DEFINING a non-surjective encoder,
       and the deployed digit map is exactly such a map.
   It is FAITHFULNESS of the composite.  Deployed signing derives the 43 digits
   from a 129-bit window (`wots.rs:119` discards the digest and keeps the
   digits), whereas the model's pipeline is `ThC : ... -> dgstblock` followed by
   `encode_msgWOTS`, and `dgstblock` carries 8*n bits.  By `c10_width_129_not_8n`
   no `n` makes 8*n = 129, so the model's composite cannot BE the deployed
   derivation for any encoder choice.  The obstruction is the intermediate WIDTH,
   not the encoder's structure and not the codomain's size.

   CONSEQUENCE FOR THIS FILE: section 2's framing was aimed one step off target.
   The cardinality gap is true and mechanized, but it is not the reason pinning
   fails; the width fact `c10_width_129_not_8n` is.  Both are stated; only the
   latter is load-bearing for the impossibility reading.
   ========================================================================== *)
lemma antichain_holds_for_any_encoder
  (E : msgWOTS -> emsgWOTS) (T : int) (m m' : msgWOTS) :
     digitsum (E m)  = T
  => digitsum (E m') = T
  => E m <> E m'
  => exists (i : int),
          0 <= i < len
       /\ BaseW.val (E m).[i] < BaseW.val (E m').[i].
proof. by move=> h1 h2 hne; apply constsum_antichain; [rewrite h1 h2 | exact hne]. qed.

(* ==========================================================================
   SECTION 6 -- THE FOUR dfC0 SEPARATIONS, AT THE DEPLOYED PARAMETER SET.

   WHAT THIS CLOSES.  SphincsC10Content.ec's residual (Q3) says PART G's model
   pins `thfc` at index `8*n + r`, so it is PARAMETER-CONDITIONAL: scheme-
   preserving only while `8*n + r` misses the four member indices, and that
   "is guaranteed by the capstone's separation premises, NOT by the model
   itself".  `MODEL_dfC_8np32_unsafe_at_n4` (8*4+32 = 8*4*2) shows the guard is
   genuinely not automatic.

   At C10's deployed n / len / k the guard becomes a THEOREM.  That is worth
   having precisely because the separations are the ONE family of capstone
   premises that does not touch `w` or the encoder -- so they are dischargeable
   at the deployed parameters even though, per the FAITHFULNESS FINDING at
   SphincsC10Content.ec:96-100, the WOTS LAYER is NOT instantiable there
   (n=16, log2_w=3, len=43).  Two premise families, two different verdicts; do
   not read this as instantiating C10.

   WHY IT IS STATED THIS WAY.  `MODEL_dfC_separations_at_port_params`
   (SphincsC10Content.ec:464) is BARE INTEGER ARITHMETIC -- `8*16+32 <> 8*16*35`
   -- which cannot discharge anything, the surrogate-disconnection failure
   recorded in experiments/tcollres-leg/Identification.ec.  The lemma below is
   instead HYPOTHETICAL ON THE MODEL'S OWN SYMBOLS (`n`, `len`, `k`,
   `emb_in`) and concludes about the REAL `dfC0` (= `size (emb_in witness)`,
   WOTS_C_Interactive.ec:405), so it composes with the capstone.

   The width hypothesis is `size (emb_in witness) = 8*n + r`, which is exactly
   what the faithful serialisation delivers (`embg_size`,
   SphincsC10Content.ec:404).  `r` stays a parameter of the lemma: it is not a
   theory constant, and the counter width enters ONLY through this equation.
   ========================================================================== *)

(* Deployed FORS parameter, from sphincs-c10/src/params.rs:34 (K = 13).
   `k` itself is an abstract const (SPHINCS_PLUS.ec:30, only 1 <= k), so this is
   a DEFINITION and the tie below is a HYPOTHESIS -- same discipline as
   c10_tie_n / c10_tie_len / c10_tie_w above. *)
op c10_k : int = 13.

lemma c10_dfC_separations (r : int) :
     n   = c10_n
  => len = c10_len
  => k   = c10_k
  => size (emb_in witness) = 8 * n + r
     (* the four widths `8*n + r` must avoid, written as the gaps themselves so
        the side conditions are self-documenting rather than magic numbers *)
     (* ROUTE (D): there are TWO projection members, of widths 8n+r+1 and
        8n+r+2 (the length tags).  EACH must avoid the four member widths, so
        every gap condition shifts by the corresponding tag length. *)
  => r + 1 <> 0
  => r + 1 <> 8 * c10_n * 2       - 8 * c10_n
  => r + 1 <> 8 * c10_n * c10_k   - 8 * c10_n
  => r + 1 <> 8 * c10_n * c10_len - 8 * c10_n
  => r + 2 <> 0
  => r + 2 <> 8 * c10_n * 2       - 8 * c10_n
  => r + 2 <> 8 * c10_n * c10_k   - 8 * c10_n
  => r + 2 <> 8 * c10_n * c10_len - 8 * c10_n
  =>    (dfC0 <> 8 * n /\ dfC0 <> 8 * n * len
        /\ dfC0 <> 8 * n * 2 /\ dfC0 <> 8 * n * k)
     /\ (dfC1 <> 8 * n /\ dfC1 <> 8 * n * len
        /\ dfC1 <> 8 * n * 2 /\ dfC1 <> 8 * n * k).
proof.
move=> hn hlen hk hsz h0 h1 h2 h3 g0 g1 g2 g3.
move: h1 h2 h3 g1 g2 g3; rewrite /c10_n /c10_len /c10_k /= => h1 h2 h3 g1 g2 g3.
rewrite /dfC0 /dfC1 emb_in0_size emb_in1_size hsz hn hlen hk
        /c10_n /c10_len /c10_k /=.
smt().
qed.

(* The deployed instance: the C10 grind counter is a u32
   (sphincs-c10/src/wots.rs:54-60, `find_count -> (u32, ...)`), so r = 32 and
   dfC0 = 8*16 + 32 = 160, which avoids {128, 5504, 256, 1664}. *)
lemma c10_dfC_separations_r32 :
     n   = c10_n
  => len = c10_len
  => k   = c10_k
  => size (emb_in witness) = 8 * n + 32
  =>    (dfC0 <> 8 * n /\ dfC0 <> 8 * n * len
        /\ dfC0 <> 8 * n * 2 /\ dfC0 <> 8 * n * k)
     /\ (dfC1 <> 8 * n /\ dfC1 <> 8 * n * len
        /\ dfC1 <> 8 * n * 2 /\ dfC1 <> 8 * n * k).
proof.
move=> hn hlen hk hsz.
by apply (c10_dfC_separations 32 hn hlen hk hsz);
   rewrite /c10_n /c10_len /c10_k.
qed.

(* ROBUSTNESS TO THE MODELLING CHOICE.  The implementation hashes the counter
   inside a 32-BYTE slot (`wots_digest`, sphincs-c10/src/hash.rs:357-363: a
   128-byte preimage whose last 32 bytes carry the u32 big-endian), so a reader
   could model the counter field as 256 bits rather than 32.  The separations
   hold either way -- 384 also avoids {128, 5504, 256, 1664} -- so the result
   does not depend on resolving that modelling question. *)
lemma c10_dfC_separations_r256 :
     n   = c10_n
  => len = c10_len
  => k   = c10_k
  => size (emb_in witness) = 8 * n + 256
  =>    (dfC0 <> 8 * n /\ dfC0 <> 8 * n * len
        /\ dfC0 <> 8 * n * 2 /\ dfC0 <> 8 * n * k)
     /\ (dfC1 <> 8 * n /\ dfC1 <> 8 * n * len
        /\ dfC1 <> 8 * n * 2 /\ dfC1 <> 8 * n * k).
proof.
move=> hn hlen hk hsz.
by apply (c10_dfC_separations 256 hn hlen hk hsz);
   rewrite /c10_n /c10_len /c10_k.
qed.

(* --------------------------------------------------------------------------
   THE OTHER CAPSTONE PREMISES — WHY THEY GET NO RECEIPT HERE.

   An adversarial review (2026-07-31) banked the residual that `hc`, `hencb` and
   the four `dfC0 <>` facts carry no satisfiability receipt in either capstone
   file (R4b covers only the two real-valued premises).  Per-family verdict:

   * THE FOUR dfC0 SEPARATIONS — DISCHARGED above at the deployed n / len / k,
     given the serialisation width.  This is the family that does not touch `w`
     or the encoder, which is exactly why it survives the WOTS-layer
     non-instantiability.

   * `hencb`  (encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc))
     — SUPERSEDED 2026-08-25, SEE THE NOTE AFTER THIS BULLET.  The verdict below
     was correct when written and is now stale in its PREMISE: `encode_msgWOTS_C`
     is no longer an abstract op.
     — NOT RECEIPTABLE HERE, and deliberately not faked.  `encode_msgWOTS_C` is
     an abstract op (WOTS_C_Real.ec:337 — that is the FORK's line; in this SPLIT
     file it was :377, and since 2026-08-25 it is :403 and DEFINED).  The available existential receipt,
     `exists E, forall .., E .. = encode_msgWOTS (ThC ..)`, is trivially true
     (take the composition) and says NOTHING about the actual op -- it is
     precisely the "weak witness" SphincsC10Content.ec's PART G header already
     criticises in PARTS D/E, and residual (Q1) records why a machine-checked
     `clone ... realize` is impossible at this seam: EasyCrypt cannot
     re-interpret an already-declared op from inside the theory.  Writing such a
     lemma would manufacture the appearance of a receipt without the substance.

   * `hc` (c <= p_tgts) — NOT A THEOREM AND NOT MEANT TO BE.  `p_tgts` is an
     abstract constant carrying only `0 <= p_tgts` (WOTS_C_Real.ec:300); `c` is
     the hypertree's WOTS-instance count (WOTS_C_Real.ec:41).  `c <= p_tgts` is a
     PARAMETER CHOICE -- the SM-DT-TCR game must be given at least as many
     targets as there are instances -- satisfiable by construction and not
     derivable from the closure.  Recording it as a premise is correct.

   So the residual is now: one family discharged, two families explained rather
   than receipted.  That is the honest resolution, not a full one.

   UPDATE 2026-08-25 — `hencb` IS NOW DISCHARGED, and the bullet above is superseded.
   `encode_msgWOTS_C` was given the body `encode_msgWOTS (ThC p a x cc)` at
   WOTS_C_Real.ec:403, so the equation is a THEOREM
   (WOTS_C_Real.ec::encode_msgWOTS_C_compat) and the headline family carries it no
   longer.  CHARGED_QWIRED 7->6 premises, _TIGHT and _TIGHT_AT_DEPLOYED_PARAMS 6->5.

   THIS IS NOT THE MOVE THE BULLET ABOVE REJECTED.  It rejected (a) an EXISTENTIAL
   receipt, which is trivially true and says nothing about the actual op, and (b) a
   `clone .. realize`, blocked because EasyCrypt cannot re-interpret an already-declared
   op FROM INSIDE the theory.  Editing the DECLARATION SITE is neither: it is the one
   place (b)'s obstruction does not apply, and it constrains THE actual op.  Section 8's
   "hencb IS LOAD-BEARING" also stands unchanged -- its consequent is that DROPPING the
   equation kills the reduction to MM45's WOTS-TW, and nothing is dropped here; the
   equation now holds by computation, so R_int_WOTSTW is preserved exactly.

   AND SECTION 8's "the whole of the unfaithfulness" DOES NOT CARRY INTO THIS TREE.
   That was written 2026-07-31, PRE-SPLIT, when `hencb` forced ThC's output to width
   8*n.  In the split `msgWOTS = mdgstblock` at independent width 8*n_m
   (WOTS_TW_ES.ec:270) and ThC already returns the wide type -- which is what the split
   was for.

   WHAT IT DOES NOT BUY.  This eliminates a MODEL-INTERNAL degree of freedom, not a
   deployment-facing assumption.  The correspondence to the deployed encoder is now
   carried entirely by `ThC`, whose own gaps are unchanged and unreceipted: `emb_in` and
   `thfc` are still free ops and the two projection members remain correlated under the
   instantiation.  `hc` (c <= p_tgts) remains the only substantive premise of the
   deployed statement, and remains a parameter choice, exactly as the bullet above says.
   -------------------------------------------------------------------------- *)

(* ==========================================================================
   SECTION 7 -- RECONCILED POSITION ON "WHAT BLOCKS DEPLOYED C10" (2026-07-31).

   Established by a bounded two-model review wave (GPT-5.6, Kimi K3; mutually
   blind, read-only, frozen tree cdf64f10) after a discrepancy was noticed
   between this file's model and the Rust implementation.  Both legs returned
   OBSTRUCTION UNSOUND independently.  Every citation below was re-verified at
   source before being recorded.

   1.  THE IMPLEMENTATION HAS TWO WIDTHS; THIS MODEL HAS ONE.
       - chain elements are 16 bytes: `chain_hash(val: &[u8; N]) -> [u8; N]`,
         sphincs-c10/src/hash.rs:322-328, N = 16 (params.rs:19);
       - the WOTS MESSAGE DIGEST is 32 bytes: `wots_digest(..) -> [u8; 32]`,
         hash.rs:350-355, and `extract_digits(digest: &[u8; 32])` (wots.rs:16)
         consumes bit offsets 0..128 -- 129 bits -- since the last digit is at
         offset 42*3 = 126 (wots.rs:27-44).
       In this model `dgstblock` is ONE type of width 8*n (WOTS_TW_ES.ec:161-168)
       serving BOTH roles: chain elements (`f = thfc (8*n)`, :428) and, via
       `msgWOTS = dgstblock` (:213), ThC's output and `encode_msgWOTS`'s domain
       (WOTS_C_Real.ec:175; WOTS_TW_ES.ec:563).  n = 16 is faithful to the chains
       and unfaithful to the digest; n = 32 is the reverse.  NO SINGLE n WORKS.

   2.  BOTH PREVIOUSLY-RECORDED BLOCKERS ARE ARTIFACTS OF THAT TIE.
       (a) The cardinality gap `c10_codomain_exceeds_domain` (2^128 < 2^129,
           :163-181) is TRUE ARITHMETIC but is NOT an obstruction: it compares
           the codeword space against a 128-bit domain that the deployment does
           not use.  Under the faithful correspondence the encoder's domain is
           the 256-bit digest (2^256 > 2^129), or -- restricted to the window
           `extract_digits` actually reads -- exactly 2^129, where the deployed
           digit map is base-8 expansion, a BIJECTION onto the codeword space.
           Neither reading yields domain < codomain.
       (b) The relocation to `c10_width_129_not_8n` (:211-212), recorded here on
           2026-07-30 as "the intermediate WIDTH is the blocker", is WRONG for
           the same reason: 129 is not the deployed intermediate width.  256 is,
           and 256 = 8 * 32 IS a multiple of 8 -- see c10_width_256_is_8n_and_fits
           below.  The retype-to-fit escape that lemma claims to kill is open.

   3.  THE CONCLUSION SURVIVES, VIA A DIFFERENT DEFECT.  "Deployed C10 is not
       faithfully instantiable in this development AS TYPED" still holds -- but
       because of (1), the one-n-two-widths tie, not because of any counting
       argument.  Do not cite (2a) or (2b) as the reason.

   4.  WHAT A REPAIR WOULD BE, AND WHY IT IS NOT ATTEMPTED HERE.  Split the
       width: keep a chain-block type at 8*n (n = 16) and introduce a separate
       message-digest type at 8*n_m (n_m = 32), retyping ThC's output and
       `encode_msgWOTS`'s domain to the latter.  Known breakage: the `STCRC_WC`
       clone binding `out_t <- dgstblock` (already flagged at :135-136) and every
       site composing ThC's output into a `dgstblock` context (~531 `ThC`
       mentions across 35 files, :135).  Reviewers spot-checked consumers only;
       the blast radius is UNVERIFIED.  This is a fork of MM45's type structure,
       not an edit.

   5.  STALENESS FOUND IN A NEIGHBOURING FINDING.  SphincsC10Content.ec:96-100
       states this theory "CANNOT be instantiated at C10's deployed WOTS
       parameters".  That finding's stated mechanisms are NOT the width argument
       and two of them no longer hold in this fork: its F1 cites MM45's
       three-literal `log2_w` restriction, but both trees now read
       `2 <= log2_w` (WOTS_TW_ES.ec:34); its F2 cites `len2 > 0` forcing
       len > len1, but the fork DROPPED len1/len2 and made `len` primitive with
       `2 <= len` for C10's 43 (WOTS_TW_ES.ec:41-53).  Its F3 (the
       two_encodings/antichain count) is independent of the width question and
       stands or falls separately; the fork relativized `two_encodings`.
       Treat :96-100 as historical until re-derived.
   ========================================================================== *)

(* The mechanized half of 2(b): a width that IS a multiple of 8 and accommodates
   the 129 bits `extract_digits` reads.  This is the escape `c10_width_129_not_8n`
   claims to kill, and it is open -- which is why 129-not-8k cannot be the
   blocker.  (The deployed digest is exactly this width: 32 bytes.) *)
lemma c10_width_256_is_8n_and_fits :
  8 * 32 = 256 /\ 129 <= 256.
proof. by []. qed.

(* ==========================================================================
   SECTION 8 -- WHERE THE WIDTH SPLIT ACTUALLY FAILS (measured, 2026-07-31).

   Section 7 named the obstruction (one `n`, two widths) and estimated the
   repair as "retype ThC's output and encode_msgWOTS's domain; ~531 ThC mentions
   across 35 files; blast radius unverified".  That estimate was replaced by a
   MEASUREMENT, and the answer is sharper and worse than a count of sites.

   METHOD.  A throwaway probe: `base-c10-fork/*.ec` copied to a scratch tree with
   every proof body gutted to `admit.` via base-c10-fork/gut.py (compile drops
   from 574s to 2s, so only TYPE errors surface and iteration is cheap; module
   procedure bodies are NOT gutted, so scheme-level type mixing still shows).
   Then `type msgWOTS = dgstblock` was replaced by a fresh `mdgstblock` subtype
   at width `8*n_m`, `n_m` independent of `n`.  Reproduce with:
     for f in base-c10-fork/*.ec; do python3 base-c10-fork/gut.py "$f" DST/$(basename $f) 0 0; done
     cp base-c10-fork/*.eca DST/ && chmod 777 DST      # container writes .eco there
     <apply the split> && easycrypt compile -I DST DST/WOTS_TW_ES.ec

   RESULT 1 -- THE WOTS LAYER SURVIVES.  With the widths split,
   WOTS_TW_ES.ec typechecks (rc=0): declarations, clones and module bodies all
   accept a message type distinct from the chain-element type.  So the WOTS
   layer is NOT where the tie is enforced.

   RESULT 2 -- THE HYPERTREE MAKES IT STRUCTURALLY IMPOSSIBLE, not merely
   expensive.  FL_SL_XMSS_MT_ES.ec fails at the signing loop:

       var root : dgstblock;
       root <- m;                                   <-- msgFLSLXMSSMTTW vs dgstblock
       while (size sapl < d) {
         sigWOTS <@ WOTS_TW_ES.sign((.., root));
         root <- val_bt_trh ps .. (list2tree leaves);
       }

   Layer k's WOTS MESSAGE IS layer k-1's ROOT.  The message type must equal the
   node type because roots are recursively signed -- so `msgWOTS = dgstblock` is
   STRUCTURAL, not an abbreviation, and no amount of retyping widens `msgWOTS`
   while keeping this loop.  (`root_from_sigFLSLXMSSMTTW` has the same shape.)

   RESULT 3 -- SO THE MISMATCH IS NOT WHERE SECTION 7 PUT IT.  The deployment
   agrees with the model here: every hypertree layer signs a 16-byte node.  What
   differs is the ENCODER'S input -- ThC(node, count) at 32 bytes, not the node.
   And `encode_msgWOTS_C : pseed -> adrs -> msgWOTS -> cntr -> emsgWOTS`
   (WOTS_C_Real.ec:337) ALREADY has the faithful shape: node in, digits out, no
   128-bit intermediate mentioned.

   THE CONFLATION IS EXACTLY ONE PREMISE.  `hencb`,
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc),
   forces ThC's output to be a `msgWOTS` -- hence `dgstblock`, hence 8*n.  That
   single equation is the whole of the unfaithfulness.

   AND IT IS LOAD-BEARING, WHICH IS WHY THIS IS HARD.  `hencb` is precisely what
   lets the +C reduction hand ThC's output to the HONEST WOTS-TW oracle as a
   message (R_int_WOTSTW, WOTS_C_Interactive.ec).  Dropping it does not just lose
   a premise -- the reduction to MM45's WOTS-TW stops existing.  Faithfully, the
   deployment's WOTS+C reduces to a WOTS-TW instance whose MESSAGES are 256 bits
   while its CHAINS are 128; MM45's WOTS-TW cannot express that instance, because
   `f = thfc (8*n)` and `msgWOTS = dgstblock` fix both to the same `n`.

   STATUS: the repair is NOT a retype of ThC's output.  It is a WOTS-TW variant
   with independent message and chain widths, plus a +C-aware hypertree whose
   loop carries `ThC(root, c)` rather than `root`.  That is a new development,
   not an edit to this one.  NOT ATTEMPTED.  Nothing above section 8 depends on
   this; it records where the wall is so the next attempt starts at the wall.
   ========================================================================== *)

(* ==========================================================================
   SECTION 9 -- SCOPING THE WOTS-TW VARIANT (measured, 2026-07-31).

   Section 8 located the wall.  This measures what a repair would actually cost,
   and the headline is that ONE of the two feared costs is ZERO.

   RESULT A -- THE WOTS-TW LAYER IS FREE.  `base-c10-fork/WOTS_TW_ES.ec` copied
   verbatim (NO gutting, both original admits intact), with `type msgWOTS =
   dgstblock` replaced by a fresh `mdgstblock` subtype at width `8*n_m`, `n_m`
   INDEPENDENT of `n`:

       easycrypt compile -I <probe> <probe>/WOTS_TW_ES.ec    ->  rc=0, 137s

   The whole `Proof_M_EUF_GCMA_WOTS_TW_ES_NPRF` section, the gated
   `MEUFGCMA_WOTSTWESNPRF` theorem and every supporting lemma go through
   UNCHANGED with the message width decoupled from the chain width.  MM45's
   chain argument does not care that messages are wider, and neither does the
   encoding surface -- `encode_msgWOTS : msgWOTS -> emsgWOTS` simply takes a
   wider domain.  ZERO proof repair in the WOTS layer.

   (Prior expectation, recorded so the miss is visible: "does the chain argument
   care? probably not; does the encoding/two_encodings surface? probably yes."
   The second half was wrong.)

   RESULT B -- CORRECTION TO SECTION 8's PESSIMISM.  Section 8 concluded the
   repair is "a new development, not an edit", on the grounds that `hencb` is the
   conflation and is load-bearing.  That is too strong, and the reason is a
   TYPE-ROLE SWAP it did not consider.

   Today `ThC : pseed -> adrs -> msgWOTS -> cntr -> dgstblock` -- input and
   output BOTH 8*n.  Faithfully the input is a hypertree NODE (16 B) and the
   output is the WOTS digest (32 B), i.e.

       ThC : pseed -> adrs -> dgstblock -> cntr -> msgWOTS

   with `msgWOTS` the WIDE type.  Under that retyping `hencb`,
   `encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)`, REMAINS
   WELL-TYPED -- `ThC`'s output is exactly what `encode_msgWOTS` now consumes --
   and the +C reduction still hands `ThC`'s output to the honest WOTS-TW oracle,
   which by RESULT A now accepts wide messages.  So `hencb` need not be dropped
   and the reduction need not be rebuilt.  Section 8's "removes the reduction"
   holds only for DELETING hencb, not for retyping around it.

   The +C hypertree already has the faithful shape: `XMSSMT_C_Scheme.ec:117-129`
   passes `root : dgstblock` to `WOTS_C_ES.sign`, which grinds internally.  It is
   MM45's UNGATED hypertree (`FL_SL_XMSS_MT_ES.ec:1078`) that signs roots with
   WOTS-TW directly and therefore breaks.

   THE REMAINING OPEN QUESTION, now sharp enough to be worth one experiment:
   does the +C chain need the ungated FL_SL hypertree's SCHEME, or only its TREE
   MACHINERY (leaves_from_sspsad, cons_ap_trh, val_bt_trh, the trh/pkco
   surfaces)?  If the latter, the split is a bounded edit after all.  If the
   former, section 8's verdict stands.  NOT MEASURED -- and note this file has
   twice now recorded a confident answer to "what blocks C10" that a measurement
   overturned, so it is left open rather than guessed a third time.
   ========================================================================== *)

(* ==========================================================================
   SECTION 10 -- THE OPEN QUESTION OF SECTION 9, SETTLED (measured 2026-07-31).

   Q: does the +C chain need MM45's UNGATED FL_SL hypertree SCHEME, or only its
      TREE MACHINERY?
   A: TREE MACHINERY.  The split is a BOUNDED EDIT, not a new development.
      Section 8's verdict is withdrawn.

   EVIDENCE 1 -- THE CLOSURE NEVER USES THE UNGATED SCHEME.  Comment-stripped
   scan of all 19 closure files for code (not prose) references:

       FL_SL_XMSS_MT_ES (module)          0        cons_ap_trh          18
       FL_SL_XMSS_MT_ES_NPRF              0        val_bt_trh           49
       EUF_NAGCMA_FLSLXMSSMTTWESNPRF      0        val_ap_trh           10
       root_from_sigFLSLXMSSMTTW          0        leaves_from_sspsad    7
       skFLSLXMSSMTTW                     0        nr_nodes_ht          32
                                                   pkco                 47
       pkFLSLXMSSMTTW                    14        list2tree           101
         (a TYPE, FL_SL_XMSS_MT_ES.ec:611, not a scheme procedure)

   The +C chain runs on its own scheme (`FL_SL_XMSS_MT_C_ES`, 104 uses) and on
   the shared tree machinery.  It touches the ungated scheme zero times.

   EVIDENCE 2 -- ONLY THE UNGATED SIDE BREAKS, AND ITS PROOFS ARE NOT NEEDED.
   With the split applied, an iterative excise-and-recompile over the gutted
   FL_SL removed exactly six modules before it compiled, every one ungated-side:
   FL_SL_XMSS_MT_ES, FL_SL_XMSS_MT_ES_NPRF, EUF_NAGCMA_FLSLXMSSMTTWESNPRF,
   R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA, R_SMDTTCRCPKCO_EUFNAGCMA,
   R_SMDTTCRCTRH_EUFNAGCMA.  No tree-machinery item ever appeared.

   EVIDENCE 3 -- AND IT HOLDS AT THE PROOF LEVEL, NOT ONLY TYPES.  The weakness
   of Evidence 2 is that gutted probes only answer "do the statements typecheck".
   So the experiment was repeated with PROOFS INTACT:
       full FL_SL_XMSS_MT_ES.ec + width split + ungated side (6 modules and
       section Proof_EUF_NAGCMA_FL_SL_XMSS_MT_ES_NPRF) excised
       -> rc=0, 58s, 0 admits remaining
   Every tree-machinery lemma still proves with the message width decoupled.
   Combined with SECTION 9's result (full WOTS_TW_ES.ec, proofs intact, rc=0,
   137s), BOTH base layers are split-compatible at the proof level.

   NOTABLE SIDE-EFFECT.  The ungated side is where the fork's admitted
   `EUFNAGCMA_FLSLXMSSMTTWESNPRF` lives -- one of the closure's TWO cone admits
   (cert-baseline.tsv).  Excising it removes that admit, and with it the taint it
   propagates.  A split fork would have a strictly smaller assumption base here.
   It would also require a cert-baseline update, so it is a deliberate decision,
   not a free win.

   WHAT REMAINS UNMEASURED, and it is the next thing to do:
     (i)  the cdrafts chain under the split.  The designed retyping is
          `ThC : pseed -> adrs -> dgstblock -> cntr -> msgWOTS` (node in, wide
          digest out -- the role swap of section 9 (B)), with `WOTS_C_ES.sign`
          taking a node.  NOT compiled.
     (ii) whether to excise MM45's ungated side from the fork's base at all, or
          instead clone WOTS_TW_ES twice (narrow-message for the ungated twin,
          wide for +C).  Excision is simpler and is what was measured; cloning
          preserves MM45 content the fork inherited.
   Neither is blocked; both are ordinary work now that the wall turned out not
   to be one.
   ========================================================================== *)

(* ==========================================================================
   SECTION 11 -- CORRECTION TO SECTION 10, AND THE CDRAFTS-LAYER FINDING.

   (A) SECTION 10 OVERSTATED ITS SCAN.  It reported "the closure never uses the
   ungated scheme", measured over the 19 CDRAFTS closure files, and generalised
   that to "the closure".  The BASE cone was not scanned, and it does use it:

       base-c10-fork/SPHINCS_PLUS.ec -- 19 code refs, including
         FL_SL_XMSS_MT_ES.gen_root (:927)      FL_SL_XMSS_MT_ES.sign (:968)
         FL_SL_XMSS_MT_ES.root_from_sigFLSLXMSSMTTW (:1002)
         FL_SL_XMSS_MT_ES_NPRF.{sign,keygen,verify,leaves_from_sklpsad}
       base-c10-fork/FORS_ES.ec -- 0.

   Found by compiling, not by re-reading: excising the ungated hypertree made
   SPHINCS_PLUS.ec fail on `unknown procedure: FL_SL_XMSS_MT_ES.gen_root`.
   Section 10's PROOF-LEVEL results (WOTS_TW_ES rc=0; FL_SL rc=0 with the
   ungated side excised) STAND -- they were measured on those files.  What does
   not stand is the scope of the "never used" claim.

   The excision plausibly just extends one level: the ungated SPHINCS+ scheme
   module `SPHINCS_PLUS_S` has 0 code refs in the +C closure.  NOT asserted as
   settled -- that is the same partial-scan inference that produced this
   correction, and it has now misfired twice.

   (B) THE CDRAFTS LAYER HAS ITS OWN ONE-WIDTH TIE, one level down from the
   msgWOTS one, and it is the more interesting of the two:

       op thfc : int -> pseed -> adrs -> dgst -> dgstblock     (ONE codomain)
       op f    : ... = thfc (8 * n)                            (chains, 16 B)
       op ThC ps tw m c = thfc (size (emb_in (m,c))) ..        (so ThC : .. -> dgstblock)

   `ThC`'s output is `dgstblock` STRUCTURALLY, because the whole development
   shares ONE tweakable-hash collection with ONE codomain.  The deployment does
   not: `chain_hash -> [u8; N]` (16 B, hash.rs:322-328) and
   `wots_digest -> [u8; 32]` (32 B, hash.rs:350-355) are different functions with
   different output widths.  So the faithful model needs a SECOND hash family,
   e.g. `op thfc : int -> pseed -> adrs -> dgst -> mdgstblock`, with

       emb_in : dgstblock * cntr -> dgst
       ThC    : pseed -> adrs -> dgstblock -> cntr -> msgWOTS
       STCRC_WC binding  msg_t <- dgstblock,  out_t <- msgWOTS

   (C) AND THAT IS WHERE THE NEXT REAL QUESTION IS.  Moving ThC to its own hash
   family changes WHICH family the S-TCR(+C) assumption is about -- which is
   faithful (wots_digest really is not chain_hash) but interacts with the
   MEMBER-AWARE argument: `dfC0` identifies ThC as the member of the SHARED
   `thfc` collection at input-length index `size (emb_in witness)`, and
   `member_sep_disj` / `member_aware_disj_discharged`
   (WOTS_C_Interactive.ec) turn that into the disjointness the +C reduction
   needs.  If ThC lives in a different collection, that argument must be
   restated over two collections.  UNVERIFIED -- and it is the first thing to
   measure next, because it decides whether the cdrafts layer is as free as the
   base layers turned out to be.

   STATUS: the cdrafts chain does NOT yet compile under the split.  The probe got
   as far as (A) before the base excision had to widen.  No claim is made here
   about the cdrafts layer's cost.
   ========================================================================== *)

(* ==========================================================================
   SECTION 12 -- TWO-COLLECTION PROBE: HOW FAR IT GOT (measured 2026-07-31).

   Question asked: does the MEMBER-AWARE argument survive when ThC moves to its
   own hash collection?  ANSWER: NOT REACHED.  What follows is what was
   established on the way, and exactly what stands between.

   PROBE.  base-c10-fork + cdrafts-fork copied verbatim (PROOFS INTACT
   throughout) to a private include path, with:
     - msgWOTS  := mdgstblock  (width 8*n_m, n_m independent of n)
     - a SECOND collection  op thfc : int -> pseed -> adrs -> dgst -> mdgstblock
     - emb_in   : dgstblock * cntr -> dgst          (node in)
     - ThC      : .. -> dgstblock -> cntr -> msgWOTS (wide digest out)
     - predC    : msgWOTS -> bool                    (the gate is on the DIGEST)
     - STCRC_WC binding  msg_t <- dgstblock,  out_t <- msgWOTS
     - msgFLXMSSMTTW := dgstblock                    (the hypertree signs NODES)
     - the ungated side excised where it blocks (see below)

   COMPILES, PROOFS INTACT:
       WOTS_TW_ES        rc=0        FL_SL_XMSS_MT_ES  rc=0 (ungated excised)
       SPHINCS_PLUS      rc=0 (ungated excised)
       Grind             rc=0        STCR_C            rc=0
       WOTS_C_Real       rc=0   <-- ThC, predC, STCRC_WC clone,
                                    wotsc_grind_targets_predC
       WOTS_C_Scheme     rc=0   <-- the +C scheme (12 sites: it signs NODES)
       XMSSMT_C_Scheme   rc=0   <-- the +C hypertree

   BASE EXCISIONS NEEDED: 13, EVERY ONE UNGATED-SIDE.  FL_SL's 6 modules + its
   ungated proof section; SPHINCS_PLUS's `SPHINCS_PLUS`, R_SKGPRF_EUFCMA,
   R_MKGPRF_EUFCMA, R_MFORSTWESNPRFEUFCMA_EUFCMA,
   R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA + its ungated proof section.  (This is
   the widened excision section 11 predicted but declined to assert; it is now
   measured, at the proof level.)

   NOT ONE PROOF FAILED.  Every error encountered across the whole probe was a
   TYPE ANNOTATION -- a msgWOTS that should be dgstblock or vice versa.  No
   tactic broke, no lemma became unprovable.  That is the substantive signal so
   far, and it is why the remaining question is worth finishing rather than
   abandoning.

   WHERE IT STOPPED, AND WHY THAT IS THE INTERESTING PLACE.
   `WOTS_C_Reduction.ec` is the +C <-> WOTS-TW BRIDGE: 28 `msgWOTS` sites, and it
   references WOTS_TW_ES directly.  Unlike the +C-only files it legitimately
   carries BOTH widths -- the +C side signs nodes, the WOTS-TW side signs ThC's
   wide output -- so a blanket rename is WRONG there and each site needs its
   role decided.  That file sits between the probe and `WOTS_C_Interactive.ec`,
   where member_sep_disj / members_in_thfc_set_neq_dfC /
   member_aware_disj_discharged live.

   SO THE MEMBER-AWARE QUESTION IS STILL OPEN.  The prior worth stating (and
   distrusting): with ThC in its own collection, a `thfc` query cannot collide
   with a `thfc_m` challenge, so the disjointness the repair was built to rescue
   might become FREE and the member-aware machinery redundant.  That is a
   comfortable story of exactly the kind this file has recorded and retracted
   five times.  It is NOT asserted.  The measurement is: decide the 28 bridge
   sites, then compile WOTS_C_Interactive and read what happens to those three
   lemmas.
   ========================================================================== *)

(* ==========================================================================
   SECTION 13 -- THE MEMBER-AWARE ARGUMENT UNDER TWO COLLECTIONS: ANSWERED.

   ANSWER: the member-aware machinery is not BROKEN by two collections -- it is
   made MOOT, at the price of RE-FOUNDING the S-TCR(+C) assumption over the
   second collection.  That price is where the work is; the machinery itself is
   collateral.

   HOW FAR THE PROBE GOT (all with PROOFS INTACT):
     WOTS_C_Reduction  rc=0  -- the +C <-> WOTS-TW bridge, 28 sites decided:
                               24 to `dgstblock` (A's +C messages are NODES) and
                               4 blocks to `msgWOTS` (the WOTS-TW-side game, the
                               bridge's `choose` return, its `y`/`d` collection
                               results, and its `forge` return -- all ThC OUTPUTS).
                               The split makes that dual role EXPLICIT IN THE
                               TYPES, where the single-`n` model hid it.
     WOTS_C_Interactive      -- 107 sites renamed; `ThC_member` and
                               `ThC_same_member` restated over `thfc_m` (both
                               typecheck: ThC IS thfc by definition).  Then the
                               FIRST genuine proof failure of the entire probe.

   THE FAILURE, AND IT IS THE ANSWER.  `S_TCR_C_Int_win_2ndpreimage` concludes

       thfc dfC0 pp (emb_tw tw) (emb_in (m, j))
     = thfc dfC0 pp (emb_tw tw) (emb_in (m', ctr))

   -- a collision IN THE `thfc` COLLECTION at member `dfC0`, which is exactly what
   makes the S_TCR_C_Int term "EXACTLY SMDTTCRC.SM_DT_TCR_C's winning collision
   for the member f := thfc dfC0" (the file says so at :443-447).  With ThC in
   `thfc_m`, the collision lives in the OTHER collection and
   `rewrite -(ThC_same_member ..)` reports `nothing to rewrite`.

   SO THE COST IS NOT THE MEMBER-AWARE LEMMAS.  It is that the S-TCR(+C)
   assumption -- its collection clone, its `SM_DT_TCR_C` instance, its oracle,
   and `dfC0` itself -- is founded on `thfc`.  Moving ThC to `thfc_m` means
   re-founding all of it over the second collection.  `member_sep_disj`,
   `members_in_thfc_set_neq_dfC` and `member_aware_disj_discharged` are
   downstream of that, not the obstacle.

   THE PRIOR, ADJUDICATED.  Section 12 recorded: "with ThC in its own collection
   a thfc query cannot collide with a thfc challenge, so the disjointness the
   member-aware repair rescues might be FREE and the machinery redundant."
   DIRECTIONALLY RIGHT, INCOMPLETE.  Free disjointness is plausible -- pkco/trh
   queries live in `thfc` and simply cannot meet a `thfc_m` challenge, which is
   the very coincidence the repair was built for -- but that payoff sits BEHIND
   the re-founding, not instead of it.  NOT verified: no probe has yet
   constructed the second clone, so "the machinery becomes redundant" remains
   unproven.  It is recorded as the next measurement, not as a result.

   SCORECARD FOR THE WHOLE SPLIT, proof-level, probe with proofs intact:
     base   WOTS_TW_ES, FL_SL_XMSS_MT_ES, SPHINCS_PLUS        rc=0
            (13 excisions, every one ungated-side)
     +C     Grind, STCR_C, WOTS_C_Real, WOTS_C_Scheme,
            XMSSMT_C_Scheme, WOTS_C_Reduction                 rc=0
     stop   WOTS_C_Interactive -- at the S-TCR(+C) collection foundation.
   Across ~150 edits the ONLY non-type-annotation failure is that one, and it is
   a genuine design question rather than a defect.
   ========================================================================== *)

(* ==========================================================================
   SECTION 14 -- SECOND COLLECTION BUILT; THE DISJOINTNESS QUESTION ANSWERED,
   AND THE ANSWER IS NOT THE COMFORTABLE ONE.

   BUILT AND COMPILING (probe, proofs intact):
     op f_m : pseed -> adrs -> dgst -> mdgstblock = thfc (8 * n_m).
     clone TweakableHashFunctions as F_M   (out_t <- mdgstblock, f <- f_m)
     clone F_M.Collection        as FC_M   (get_diff <- size, fc <- thfc_m,
                                            in_collection by exists (8*n_m))
   WOTS_TW_ES rc=0 with both collections side by side.  Not `import`ed, so FC's
   names stay unambiguous.

   FREE, AS PREDICTED: `STCRC_WC.Col` needed NO change.  `STCRC` clones its own
   collection from its `out_t` (STCR_C.ec:96), and `out_t` is already `msgWOTS`
   under the split -- so the S-TCR(+C) game's collection oracle self-adjusts to
   the wide family.  Restating `ThC_member`, `ThC_same_member`,
   `S_TCR_C_Int_win_2ndpreimage` and `S_TCR_C_Int_win_implies_SMDTTCRC` over
   `thfc_m` is mechanical and compiles.

   THE WALL, AT WOTS_C_Interactive.ec:1744.  `R_int_WOTSTW` -- the +C -> WOTS-TW
   reduction -- has signature

       module (R_int_WOTSTW (A : Adv_MEUFGCMA_WOTSC) : Adv_MEUFGCMA_WOTSTWESNPRF)
              (O : Oracle_MEUFGCMA_WOTSTWESNPRF, OC : FC.Oracle_THFC)

   and it COMPUTES ThC THROUGH `OC` -- the grind loop `y <@ OC.query(emb_tw ad,
   emb_in (m, seed)); if (predC y) ...` then `d <@ OC.query(emb_tw ad,
   emb_in (m, c))` (:1739-1747).  `OC` is the NARROW collection oracle, because
   that is what MM45's `Adv_MEUFGCMA_WOTSTWESNPRF` supplies.  With ThC in
   `thfc_m`, those queries must go to an `FC_M.Oracle_THFC` THAT THE WOTS-TW GAME
   DOES NOT PROVIDE.

   SO THE TRADE IS NOT "machinery for nothing".  It is:
     GAIN  the member-aware repair becomes unnecessary -- a `thfc` query cannot
           collide with a `thfc_m` challenge, so the pkco-at-`emb_tw ad`
           coincidence that forced the repair cannot arise.  Disjointness IS
           free, exactly as section 12 guessed.
     COST  the +C reduction stops being an `Adv_MEUFGCMA_WOTSTWESNPRF`.  It would
           need `(O, OC : FC.Oracle_THFC, OC_M : FC_M.Oracle_THFC)`, i.e. an
           ADVERSARY-INTERFACE CHANGE to MM45's WOTS-TW game.

   AND THAT EXPLAINS THE CONFLATION.  Sharing one collection is what lets the +C
   reduction be an honest WOTS-TW adversary using ONLY the oracles that game
   offers.  The single-`n` tie is not sloppiness; it is load-bearing for the
   reduction's TYPE.  The member-aware repair is the price MM45's interface
   charges for keeping ThC inside the shared collection.

   HONEST SCOPE: the GAIN half is an argument from the two families being
   distinct, not a compiled proof -- no probe has yet built the two-oracle
   reduction and re-derived disjointness inside it.  The COST half IS compiled:
   the signature at :1715-1716 and the failure at :1744 are mechanical facts.
   Anyone continuing should treat "disjointness free" as very likely and
   "interface change required" as established.
   ========================================================================== *)

(* ==========================================================================
   SECTION 15 -- THE TWO-ORACLE REDUCTION, BUILT; DISJOINTNESS VERIFIED.

   BUILT AND COMPILING (probe, proofs intact, WOTS_TW_ES rc=0):

     module type Adv_MEUFGCMA_WOTSTWESNPRF(O, OC : Oracle_THFC,
                                             OC_M : FC_M.Oracle_THFC)
     module M_EUF_GCMA_WOTSTWESNPRF(A, O, OC, OC_M)

   The game body is COPIED VERBATIM from M_EUF_GCMA_WOTSTWESNPRF with two
   changes: `OC_M.init(ps)` alongside `OC.init(ps)`, and `A(O, OC, OC_M)`.  The
   WIN CONDITION IS UNCHANGED -- `adlOC` still comes from `OC` alone, so the wide
   oracle is a pure evaluation facility contributing no tweaks to the
   disjointness check.

   And the reduction, `R_int_WOTSTW` retyped to
     (O : Oracle_MEUFGCMA_WOTSTWESNPRF, OC : FC.Oracle_THFC,
      OC_M : FC_M.Oracle_THFC) : Adv_MEUFGCMA_WOTSTWESNPRF
   with ThC's grind loop and digest query moved from `OC` to `OC_M`.

   DISJOINTNESS -- VERIFIED, AND IT IS FREE.  Enumerating every collection-oracle
   call inside the reduction:

       OC_M  <-  emb_tw ad, emb_in (m, seed)      (the grind loop)
       OC_M  <-  emb_tw ad, emb_in (m, c)         (the digest)
       OC    <-  (none)

     emb_tw reaches the NARROW oracle : FALSE
     emb_tw reaches the WIDE oracle   : TRUE

   So `emb_tw ad` CANNOT ENTER the narrow transcript `adlOC`.  The member-aware
   repair exists precisely because a pkco query at `emb_tw ad` coincides with
   ThC's target tweak (WOTS_C_Interactive.ec's member-aware note); with two
   collections that coincidence is STRUCTURALLY UNREACHABLE, not merely
   improbable.  Section 12's prediction is confirmed.

   SCOPE OF "VERIFIED": this is a structural fact about the reduction module --
   the narrow oracle is never called with an `emb_tw` tweak -- established by
   enumerating its calls, not by a compiled pRHL proof of the disjointness
   invariant.  It is the strongest available statement short of the full
   downstream cascade, and it makes the invariant's PREMISE unreachable rather
   than merely discharging it.

   THE COST, NOW COUNTED.  Changing the adversary type propagates: 7
   instantiations of `R_int_WOTSTW(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default)`
   in WOTS_C_Interactive alone need the third oracle, and every downstream
   consumer (interactive_hop2, interactive_D1, interactive_D1_MA, XmssmtCC_All's
   seven, the capstones) follows.  ALSO OUTSTANDING and larger: relating
   `M_EUF_GCMA_WOTSTWESNPRF_2` back to MM45's one-oracle game -- an adversary
   with an oracle for an INDEPENDENT hash family at the hidden `pp` is not
   obviously no stronger, and that is a cryptographic step, not a retyping.
   NEITHER attempted.

   NET: the member-aware machinery can be retired, and the price is an interface
   change plus that one game-relation obligation.  Whether that trade is worth
   making is a design decision, not a measurement.
   ========================================================================== *)

(* ==========================================================================
   SECTION 16 -- CORRECTION TO SECTION 15, FOUND BY ATTACKING MY OWN CLAIM.

   Section 15 said: "emb_tw ad CANNOT ENTER the narrow transcript adlOC ... the
   coincidence is STRUCTURALLY UNREACHABLE".  THAT IS FALSE, and the refutation
   is one line of the reduction:

       module AA = A(O_wrap, OC)          (WOTS_C_Interactive.ec, R_int_WOTSTW)

   The wrapped adversary `A` is handed the NARROW collection oracle DIRECTLY.
   `A` is adversarial.  Nothing prevents it from calling `OC.query(emb_tw ad, ..)`
   itself.  So `emb_tw ad` CAN appear in `adlOC`; what the two-collection split
   removes is only that the REDUCTION ITSELF is forced to put it there on every
   signing query.

   WHAT SURVIVES, STATED PRECISELY:
     BEFORE  the reduction NECESSARILY recorded `emb_tw ad` in the narrow
             transcript on every query, so the coincidence was GUARANTEED and
             the member-aware repair was MANDATORY.
     AFTER   the reduction records nothing there; the coincidence becomes
             ADVERSARY-CHOSEN rather than structural.
   That is a real weakening of the obligation but NOT its elimination.

   AND THE OPEN PART, which section 15 skated: `FC.disj_lists` compares TWEAKS
   (adrs), not (family, tweak) pairs.  So an adversarial `A` querying the narrow
   oracle at `emb_tw ad` still collides with the tweak-only condition as written,
   even though its query is in a DIFFERENT hash family from the challenge.
   Making the two-collection setting actually pay off therefore needs the
   condition to become FAMILY-AWARE -- which is the same shape of repair as the
   member-aware one, one level up.  Whether that is cheaper than what it
   replaces is NOT established here.

   SO SECTION 15's CONCLUSION ("the member-aware machinery can be retired") IS
   WITHDRAWN pending that question.  Its other content stands: the two-oracle
   game and reduction are built and compile, the win condition is unchanged, and
   the interface cost (7 instantiations + downstream + the game-relation
   obligation) is counted.

   METHOD NOTE, because it is the point: this was found by asking "could emb_tw
   reach OC by ANOTHER route?" and enumerating what `A` is instantiated with --
   the same question put to the reviewers as check 2.  Enumerating the
   REDUCTION's own calls (section 15's evidence) was necessary and not
   sufficient: it answered "does the reduction do it" and I read it as "can it
   happen".
   ========================================================================== *)

(* ==========================================================================
   SECTION 17 -- REVIEW WAVE ON THE TWO-ORACLE WORK: VERDICT FLAWED.
   Section 15's payoff is WITHDRAWN, and section 16's correction was itself
   too gentle.

   GPT-5.6 leg (read-only, frozen 5cce118/4e02cf2, probe manifested) returned
   FLAWED.  Every load-bearing citation below re-verified at source.

   F1 (CRITICAL) -- and it is stronger than section 16 admitted.  Section 16
   said the coincidence becomes "ADVERSARY-CHOSEN rather than structural".  In
   fact THE CONCRETE CALLER DOES IT UNCONDITIONALLY.  The hypertree leaf
   reduction signs through the +C oracle and then compresses the returned public
   key with a pkco query through the NARROW collection oracle at the SAME
   address (XMSSMT_C_Reduction.ec:524-530).  `emb_tw` sets index-3 to `pkcotype`
   while preserving kp/tree/layer, so that pkco tweak IS `emb_tw ad` -- and this
   repository already says so:

       "the leaf reduction's pkco tweak coincides with a ThC target tweak, but
        sits at a DIFFERENT member, so the member-tagged transcript stays
        dfC0-free."                        (XMSSMT_C_Reduction.ec:680-684)

   So what rescues the situation is MEMBER SEPARATION -- exactly the machinery
   section 15 proposed to retire.  Under two collections that becomes FAMILY
   separation: the same argument, renamed.  THE PAYOFF LARGELY EVAPORATES.

   F2 (HIGH) -- "one game-relation obligation" is WRONG; there are at least two.
     (a) Relating the two-oracle game to MM45's needs an ASSUMPTION, not a
         proof: `thfc` and `thfc_m` are separate UNINTERPRETED ops
         (WOTS_TW_ES.ec:435-438), i.e. distinct SYMBOLS -- not probabilistically
         independent.  `thfc_m(pp,..)` may correlate with the hidden `pp`.
         Closing it needs either an auxiliary-oracle WOTS assumption or a joint
         domain-separation / independent-RF simulation.
     (b) `R_int_STCRC` still needs the NARROW `FC` for chain evaluation
         (WOTS_C_Interactive.ec:553-603) while S-TCR now uses the WIDE
         collection -- a second auxiliary-oracle obligation, and its bridge is
         already explicitly deferred (:487-494).

   F3 (MEDIUM) -- "cost counted" was 7 TEXTUAL OCCURRENCES of one instantiation
   pattern plus an unattempted downstream list.  That is not a dependency
   census, and section 15 presented it as one.  "Verified", "free", "confirmed",
   "structurally unreachable" all outran their evidence; the scope disclaimer at
   the end of section 15 does not cure a bad enumeration, because the
   enumeration itself was the wrong question (the reduction's calls, not the
   reachable calls).

   WHAT SURVIVED REVIEW (INFO-level, confirmed):
     - the two-oracle game is faithful: only the third parameter, the `choose`
       effect, `A(O,OC,OC_M)` and `OC_M.init(ps)` differ; win condition
       unchanged and `adlOC` still from `OC` alone;
     - `F_M`/`FC_M` are well-formed, `in_collection` witnessed at `8*n_m`,
       no import ambiguity -- but this establishes DISTINCT SYMBOLS, not
       cryptographic independence;
     - the retyping's role flow is semantically right (node in / digest out,
       predC on the digest, +C and hypertree sign nodes, bridge returns digests);
     - the 13 excisions are genuinely ungated-side with no +C dependency found,
       though the admitted theorem is DELETED, not discharged.

   NET POSITION ON THE WIDTH SPLIT, honestly: the base layers are free
   (section 9/10, proof-level), the +C retyping is mechanical (section 12), and
   the two-oracle construction is buildable -- but it does NOT retire the
   member-aware machinery, and it ADDS two auxiliary-oracle assumptions.  On
   present evidence the split's cost/benefit is WORSE than section 15 claimed
   and the honest recommendation is: do not adopt it to remove member-awareness,
   because it does not.
   ========================================================================== *)

(* ==========================================================================
   SECTION 18 -- RECONCILIATION OF THE TWO LEGS.  SECTION 17 OVER-CORRECTED.

   Both legs returned FLAWED and CONVERGED on the defect (section 15's
   enumeration missed `module AA = A(O_wrap, OC)`).  They DIVERGED on the
   consequence, and that divergence is where the information was.  Reproduced at
   source rather than voted on:

     GPT-5.6: the concrete leaf reduction puts `emb_tw ad` into the narrow
              transcript, member separation rescues it, so the payoff evaporates.
     Kimi K3: that narrow-transcript traffic was ALWAYS there and is HARMLESS;
              the repair's actual problem was the S-TCR side, which IS clean.

   KIMI IS RIGHT, AND SECTION 17 IS WITHDRAWN.  Two facts settle it:

     (i)  `R_int_STCRC (A) (O : STCRC_WC.Oracle_STCRC, OC : FC.Oracle_THFC)`
          with `module AA = A(O_wrap, OC)` (WOTS_C_Interactive.ec:553-554,615)
          -- A is handed the +C signing wrapper and the NARROW oracle ONLY.
          A NEVER HOLDS A WIDE-COLLECTION ORACLE.
     (ii) `STCRC_WC.Col` is cloned with
          `op fc <- fun _ pp tw x => ThC pp tw x.`1 x.`2` (STCR_C.ec:96-103),
          so the S-TCR transcript is over ThC -- the WIDE family under the split.

   Hence the wide transcript contains ONLY the reduction's own ThC queries, and
   the S-TCR disjointness -- which is what the member-aware repair exists to
   rescue -- is clean BY CONSTRUCTION.

   AND THE NARROW TRAFFIC IS A DIFFERENT CONDITION ENTIRELY.  `emb_tw ad` in
   `adlOC` bears on the WOTS-TW game's `disj_wgpidxs adlO adlOC`, which is
   discharged by the `embdisj` premise -- `get_wgpidxs` retains index 3 and
   `pkcotype <> chtype` -- and which the capstone discharges with the PROVEN
   `emb_disj_concrete`, before and after the split alike.  It was never the
   member-aware repair's problem.  Section 17 conflated the two disjointness
   conditions.

   SO THE CORRECT STATEMENT OF THE PAYOFF IS:
     NOT  "emb_tw cannot enter adlOC"                        (section 15 -- FALSE)
     NOT  "the payoff evaporates"                            (section 17 -- FALSE)
     BUT  "A holds no wide oracle, and the reduction's own ThC calls left the
          narrow transcript" -- so the member-aware repair IS moot, for a reason
          section 15 did not give.

   OTHER FINDINGS ACCEPTED:
     * "BUILT AND COMPILING" overstates the reduction: WOTS_C_Interactive.ec
       does NOT compile end-to-end -- stale two-oracle instantiations remain.
       Honest wording: "typechecks up to the first stale instantiation".
     * "7 instantiations" was a bad count: ~4 game-lemma sites plus ~8 equiv
       applications in that file, and ~25 `R_int_WOTSTW` mentions in
       XmssmtCC_All.ec.  Section 15's "cost counted" is retracted as a census.
     * THE OUTSTANDING ASSUMPTION IS NAMEABLE, and this is the most useful thing
       either leg produced: `forge(ps)` REVEALS `ps`, and `thfc_m` is a pure op
       any adversary can then evaluate itself -- so `OC_M`'s only real content is
       PRE-`ps` access to `thfc_m` under the hidden seed.  The obligation is
       therefore a PRF-AT-HIDDEN-KEY assumption on the second family (or a
       direct re-founding of WOTS-TW EUF-GCMA on the two-oracle game), not a
       vague "independence" hand-wave.
     * Comment rot at the seam (WOTS_C_Real.ec:78-79,167;
       WOTS_C_Interactive.ec:182,1700-1706 still say ThC = thfc / "grinds via
       OC").  Minor, but stale sentences are this subsystem's documented failure
       mode.
     * Probe `.eco` staleness: WOTS_TW_ES.ec was edited after the other objects
       were built, so sections 13-14's rc=0 were against an earlier WOTS_TW_ES.
       Diff is additive plus one changed line, so low risk -- but the receipts
       are not perfectly aligned and should not be quoted as if they were.

   NET, FINALLY: the width split's base layers are free, the +C retyping is
   mechanical, the two-oracle construction is buildable, and it DOES retire the
   member-aware machinery -- at the price of a PRF-at-hidden-key assumption on
   `thfc_m` plus the R_int_STCRC narrow-oracle bridge.  Whether that trade is
   worth making is a design decision.  It is NOT the "do not adopt" of
   section 17.
   ========================================================================== *)
