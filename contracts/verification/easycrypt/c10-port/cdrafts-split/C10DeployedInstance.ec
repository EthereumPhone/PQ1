(* ==========================================================================
   C10DeployedInstance.ec — THE DEPLOYED PARAMETER SET, IN THE SPLIT FORK.

   PURPOSE.  cdrafts-fork/C10DeployedGeometry.ec records (sections 7-18) that the
   UNSPLIT development cannot be instantiated at C10's deployed WOTS geometry,
   and locates the cause: one width parameter `n` where the deployment has two
   (16-byte chain elements, 32-byte WOTS message digest).  base-c10-split/
   implements the split.  This file states, at the split fork's OWN constraints,
   that the deployed parameters are admissible there — and that the width
   obstruction which blocked the unsplit development is GONE.

   Deployed values, all from sphincs-c10/src/params.rs:
       N        = 16   (:19)   security parameter / CHAIN width
       LOG_W    = 3    (:46)
       W        = 8    (:43)
       L        = 43   (:49)
       TARGET_SUM = 205 (:52)
   and the MESSAGE-DIGEST width, from the implementation rather than params.rs:
       n_m      = 32           wots_digest -> [u8; 32]  (hash.rs:350-355)

   DISCIPLINE, inherited from C10DeployedGeometry.ec: the `c10_*` ops below are
   DEFINITIONS; every statement that is supposed to say something about the
   MODEL is HYPOTHETICAL on the model's own constants (`n = c10_n`, etc.), so it
   composes rather than being a disconnected surrogate.  That failure mode is
   recorded in experiments/tcollres-leg/Identification.ec and was flagged by a
   reviewer against the geometry file.
   ========================================================================== *)
require import AllCore List IntDiv Ring StdOrder BitEncoding.
import BS2Int.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme.
require import WOTS_C_Interactive.
require import SphincsC10Content.   (* embg / embg_inj -- the generic serialisation facts *)
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import EmsgWOTS.
import IntOrder.
import WOTS_C_Real.
import WOTS_C_Interactive.

(* -------------------------------------------------------------------------
   1.  THE DEPLOYED CONSTANTS.
   ------------------------------------------------------------------------- *)
op c10_n        : int = 16.
op c10_n_m      : int = 32.    (* the WOTS message digest is 32 BYTES *)
op c10_log2_w   : int = 3.
op c10_w        : int = 8.
op c10_len      : int = 43.
op c10_target_sum : int = 205.

(* -------------------------------------------------------------------------
   2.  ADMISSIBILITY AT THE SPLIT FORK'S OWN CONSTRAINTS.

   base-c10-split/WOTS_TW_ES.ec carries exactly these four:
       ge1_n     : 1 <= n          (:28)
       ge1_nm    : 1 <= n_m        (:39)
       val_log2w : 2 <= log2_w     (:45)
       ge2_len   : 2 <= len        (:64)
   Every deployed value satisfies its own.  This is the statement the UNSPLIT
   development could not make: there `n` had to serve both roles at once.
   ------------------------------------------------------------------------- *)
lemma c10_admissible_n     : 1 <= c10_n.       proof. by rewrite /c10_n. qed.
lemma c10_admissible_n_m   : 1 <= c10_n_m.     proof. by rewrite /c10_n_m. qed.
lemma c10_admissible_log2w : 2 <= c10_log2_w.  proof. by rewrite /c10_log2_w. qed.
lemma c10_admissible_len   : 2 <= c10_len.     proof. by rewrite /c10_len. qed.

lemma c10_deployed_parameters_are_admissible :
     1 <= c10_n
  /\ 1 <= c10_n_m
  /\ 2 <= c10_log2_w
  /\ 2 <= c10_len.
proof.
  by rewrite c10_admissible_n c10_admissible_n_m
             c10_admissible_log2w c10_admissible_len.
qed.

(* -------------------------------------------------------------------------
   3.  THE WIDTH OBSTRUCTION IS GONE.  This is the split's payoff, stated.

   C10DeployedGeometry.ec:163-181 records, for the UNSPLIT development:
       codeword space  w ^ len   = 8 ^ 43  = 2 ^ 129
       message space   2 ^ (8*n) = 2 ^ 128
       hence           2 ^ 128 < 2 ^ 129            -- codomain exceeds domain
   Section 14 of that file retracts reading this as an obstruction to C10 per
   se, but it IS a real obstruction to pinning the encoder while the message
   width is tied to the CHAIN width.  Under the split the encoder's domain is
   the MESSAGE-digest space 2^(8*n_m) = 2^256, which comfortably covers the
   codeword space.
   ------------------------------------------------------------------------- *)
lemma c10_pow8 : 8 = 2 ^ 3.
proof. by rewrite (_ : 3 = 2 + 1) 1:// exprS 1:// (_ : 2 = 1 + 1) 1:// exprS 1:// expr1. qed.

lemma c10_codeword_space : c10_w ^ c10_len = 2 ^ 129.
proof. by rewrite /c10_w /c10_len c10_pow8 -exprM; congr. qed.

lemma c10_message_digest_space : 2 ^ (8 * c10_n_m) = 2 ^ 256.
proof. by rewrite /c10_n_m. qed.

(* THE PAYOFF: at the deployed geometry the encoder's domain now COVERS its
   codomain, where before it fell short by exactly one bit. *)
lemma c10_split_removes_the_width_obstruction :
  c10_w ^ c10_len <= 2 ^ (8 * c10_n_m).
proof.
  rewrite c10_codeword_space c10_message_digest_space.
  have -> : 256 = 129 + 127 by ring.
  rewrite exprD_nneg 1,2://.
  smt(expr_gt0 exprn_ege1).
qed.

(* And, for the record, the inequality the unsplit development had -- kept so
   the contrast is visible in one place rather than across two forks. *)
lemma c10_unsplit_fell_short : 2 ^ (8 * c10_n) < c10_w ^ c10_len.
proof.
  rewrite c10_codeword_space /c10_n /=.
  have -> : 129 = 128 + 1 by ring.
  rewrite exprS 1://.
  smt(expr_gt0).
qed.

(* -------------------------------------------------------------------------
   4.  TARGET_SUM = 205 IS GEOMETRICALLY ATTAINABLE.

   `target_sum` is DEFINED as `digitsum (encode_msgWOTS tgt_witness)`
   (base-c10-split/WOTS_TW_ES.ec:637), and `digitsum` sums `len` base-w digits
   (:627), so it lands in [0, len * (w-1)].  At the deployed geometry that is
   [0, 301], and 205 lies inside it.

   HONEST SCOPE, because this is exactly the kind of claim this project has
   over-read before: this says 205 is NOT EXCLUDED BY THE GEOMETRY.  It does NOT
   say 205 is in the image of `digitsum o encode_msgWOTS` -- that needs the
   ENCODER pinned to the deployed digit map, which is still open (residual Q2 of
   cdrafts-fork/SphincsC10Content.ec).  A necessary condition, not a sufficient
   one.
   ------------------------------------------------------------------------- *)
lemma c10_digitsum_range : 0 <= c10_target_sum <= c10_len * (c10_w - 1).
proof. by rewrite /c10_target_sum /c10_len /c10_w. qed.

lemma c10_target_sum_not_excluded_by_geometry :
  0 <= c10_target_sum /\ c10_target_sum <= c10_len * (c10_w - 1).
proof. by have := c10_digitsum_range. qed.

(* -------------------------------------------------------------------------
   5.  THE TIE.  Everything above is arithmetic about `c10_*`.  These are the
   statements ABOUT THE MODEL, hypothetical on the model's own constants, so
   they compose with the development rather than sitting beside it.
   ------------------------------------------------------------------------- *)
lemma c10_tie_n     : n     = c10_n     => 1 <= n.
proof. by move=> ->; exact c10_admissible_n. qed.

lemma c10_tie_n_m   : n_m   = c10_n_m   => 1 <= n_m.
proof. by move=> ->; exact c10_admissible_n_m. qed.

lemma c10_tie_log2w : log2_w = c10_log2_w => 2 <= log2_w.
proof. by move=> ->; exact c10_admissible_log2w. qed.

lemma c10_tie_len   : len   = c10_len   => 2 <= len.
proof. by move=> ->; exact c10_admissible_len. qed.

(* The model-level form of section 3: with the deployed widths in place, the
   encoder's domain covers the codeword space. *)
lemma c10_tie_width_ok :
  w = c10_w => len = c10_len => n_m = c10_n_m => w ^ len <= 2 ^ (8 * n_m).
proof.
  move=> -> -> ->; exact c10_split_removes_the_width_obstruction.
qed.

(* The model-level form of section 4's NECESSARY condition. *)
lemma c10_tie_target_sum_in_range :
  len = c10_len => w = c10_w =>
  0 <= c10_target_sum <= len * (w - 1).
proof. by move=> -> ->; exact c10_digitsum_range. qed.

(* -------------------------------------------------------------------------
   6.  205 IS ATTAINED, not merely in range.

   Section 4 showed 205 lies in [0, len*(w-1)].  That is a range statement and
   says nothing about whether any CODEWORD actually has that digit sum.  Here it
   is exhibited: 41 digits of 5 and 2 of 0, over len = 43 digits of base w = 8.
       41 * 5 = 205,   5 <= w - 1 = 7,   41 <= len = 43.
   So the deployed target sum is realised by an actual element of the codeword
   space, at the deployed geometry.

   STILL NOT residual Q2.  Q2 asks whether 205 is in the image of
   `digitsum o encode_msgWOTS` -- i.e. whether the DEPLOYED ENCODER reaches such
   a codeword.  That needs `encode_msgWOTS` pinned to the deployed digit map,
   which in turn needs the concrete hash, and is out of reach here.  What this
   closes is the GEOMETRIC half: the target is not ruled out by the codeword
   space's shape.
   ------------------------------------------------------------------------- *)
op c10_witness_digits : int -> int = fun i => if i < 41 then 5 else 0.

lemma c10_witness_digits_in_range (i : int) :
  0 <= c10_witness_digits i <= c10_w - 1.
proof. by rewrite /c10_witness_digits /c10_w; case (i < 41). qed.

lemma c10_witness_digits_sum :
  StdBigop.Bigint.BIA.bigi predT c10_witness_digits 0 c10_len = c10_target_sum.
proof.
  rewrite /c10_len /c10_target_sum.
  rewrite (StdBigop.Bigint.BIA.big_cat_int 41 0 43) 1,2://.
  rewrite (StdBigop.Bigint.BIA.eq_big_int 0 41 _ (fun _ => 5)).
  + by move=> i [ge0i lti]; rewrite /c10_witness_digits lti.
  rewrite (StdBigop.Bigint.BIA.eq_big_int 41 43 _ (fun _ => 0)).
  + by move=> i [ge41i lti]; rewrite /c10_witness_digits; smt().
  rewrite !StdBigop.Bigint.big_constz !count_predT !size_range /=.
  by smt().
qed.

lemma c10_target_sum_attained :
  exists (f : int -> int),
       (forall i, 0 <= f i <= c10_w - 1)
    /\ StdBigop.Bigint.BIA.bigi predT f 0 c10_len = c10_target_sum.
proof.
  exists c10_witness_digits; split.
  + exact c10_witness_digits_in_range.
  exact c10_witness_digits_sum.
qed.

(* -------------------------------------------------------------------------
   7.  target_sum = 205 IS REALISABLE IN THE MODEL.

   WHY THIS IS NOW A REACHABLE STATEMENT.  In this fork `encode_msgWOTS` carries
   NO AXIOM AT ALL: the two encoding axioms were retired when `P` became a
   DEFINITION on the constant-sum surface (base-c10-split/WOTS_TW_ES.ec:617-644),
   and `target_sum` is itself DEFINED as `digitsum (encode_msgWOTS tgt_witness)`
   (:637).  So `target_sum = 205` is not blocked by any consistency requirement
   on the encoder -- it only needs a CODEWORD with that digit sum to exist, and
   an encoder/witness pair landing on one.

   Section 6 gave the digit vector; this lifts it into an actual `emsgWOTS` and
   evaluates `digitsum` on it, which is the model-level statement.
   ------------------------------------------------------------------------- *)
op c10_witness_word : emsgWOTS =
  EmsgWOTS.mkemsgWOTS (mkseq (fun i => BaseW.insubd (c10_witness_digits i)) len).

lemma c10_witness_word_digits (i : int) :
  w = c10_w => 0 <= i < len => BaseW.val c10_witness_word.[i] = c10_witness_digits i.
proof.
  move=> hw rng.
  rewrite EmsgWOTS.getE rng /= /c10_witness_word EmsgWOTS.ofemsgWOTSK.
  + by rewrite size_mkseq; smt(ge2_len).
  rewrite nth_mkseq 1:// /=.
  rewrite BaseW.insubdK //.
  by have := c10_witness_digits_in_range i; rewrite hw /c10_w; smt().
qed.

lemma c10_witness_word_digitsum :
  w = c10_w => len = c10_len => digitsum c10_witness_word = c10_target_sum.
proof.
  move=> hw hlen.
  rewrite /digitsum.
  rewrite (StdBigop.Bigint.BIA.eq_big_int 0 len _ c10_witness_digits).
  + by move=> i rng /=; exact (c10_witness_word_digits i hw rng).
  by rewrite hlen; exact c10_witness_digits_sum.
qed.

(* THE STATEMENT.  At the deployed geometry there is a codeword whose digit sum
   is exactly the deployed TARGET_SUM, so an encoder/witness pair making
   `target_sum = 205` exists and the model can be instantiated with it. *)
lemma c10_target_sum_205_realisable :
  w = c10_w => len = c10_len => exists (e : emsgWOTS), digitsum e = c10_target_sum.
proof.
  by move=> hw hlen; exists c10_witness_word; exact (c10_witness_word_digitsum hw hlen).
qed.

(* -------------------------------------------------------------------------
   8.  THE DEPLOYED SERIALISATION, AND THE dfC SEPARATIONS AT OUR PARAMETERS.

   `emb_in : dgstblock * cntr -> dgst` is the +C hash's message input.  The
   deployment serialises it as NODE || COUNTER: wots_digest's preimage carries
   the 16-byte node and the u32 counter (sphincs-c10/src/hash.rs:350-363,
   find_count returning u32 at wots.rs:54-60).  So the deployed width is
       dfC = size (emb_in witness) = 8*n + r  with n = 16, r = 32  =>  160.

   The development requires FOUR separations of `dfC` from the other collection
   members (WOTS_C_Interactive.ec; they are premises of the capstone).  At the
   deployed n / len / k they are DECIDABLE, and 160 avoids all four:
       8n = 128,  8n*len = 5504,  8n*2 = 256,  8n*k = 1664.
   ------------------------------------------------------------------------- *)
op c10_k : int = 13.        (* params.rs:34 *)
op c10_r : int = 32.        (* the grind counter is a u32 *)

(* ROUTE (D): there are TWO message-compression members, one per projection.
   The length tags make them distinct: dfC0 = 1 + 160 = 161, dfC1 = 2 + 160 =
   162.  Both must clear all four separations, and they must differ from each
   other -- the concrete discharge of ThC_members_distinct at our parameters. *)
lemma c10_dfC_deployed_values :
  n = c10_n => size (emb_in witness) = 8 * n + c10_r => dfC0 = 161 /\ dfC1 = 162.
proof.
  move=> hn hsz; rewrite /dfC0 /dfC1 emb_in0_size emb_in1_size hsz hn /c10_n /c10_r.
  smt().
qed.

lemma c10_dfC_separations_deployed :
     n   = c10_n
  => len = c10_len
  => k   = c10_k
  => size (emb_in witness) = 8 * n + c10_r
  =>    (dfC0 <> 8 * n /\ dfC0 <> 8 * n * len /\ dfC0 <> 8 * n * 2 /\ dfC0 <> 8 * n * k)
     /\ (dfC1 <> 8 * n /\ dfC1 <> 8 * n * len /\ dfC1 <> 8 * n * 2 /\ dfC1 <> 8 * n * k)
     /\ dfC0 <> dfC1.
proof.
  move=> hn hlen hk hsz.
  have [hd0 hd1] : dfC0 = 161 /\ dfC1 = 162 by exact (c10_dfC_deployed_values hn hsz).
  rewrite hd0 hd1 hn hlen hk /c10_n /c10_len /c10_k /=.
  smt().
qed.

(* AND THE HYPOTHESIS IS SATISFIABLE at the deployed geometry: the NODE||COUNTER
   serialisation has exactly that width, is constant-width, and is injective
   provided the counter space fits in r bits (2^32 counters, r = 32).  This is
   the deployed instantiation meeting what the model asks of `emb_in`. *)
op c10_embg (x : dgstblock * cntr) : dgst =
  DigestBlock.val x.`1 ++ int2bs c10_r (index x.`2 STCRC_WC.G.CntrFT.enum).

(* 2026-09-21: the actual STCRC_WC clone now consumes the full-u32 type and
   ascending enumeration. These facts no longer need a cardinality premise. *)
lemma c10_counter_cardinality : STCRC_WC.G.CntrFT.card = 4294967296.
proof. exact C10Counter.cardinality. qed.

lemma c10_counter_cardinality_bound : STCRC_WC.G.CntrFT.card <= 2 ^ c10_r.
proof. exact C10Counter.cardinality_bound. qed.

lemma c10_counter_rank (c : cntr) :
  index c STCRC_WC.G.CntrFT.enum = C10Counter.U32.val c.
proof. exact C10Counter.rank_numeric. qed.

lemma c10_emb_in_pinned : emb_in = c10_embg.
proof.
  by apply fun_ext => x; rewrite /emb_in /C10Bytes.compact /C10Bytes.counter_bits
    /c10_embg /c10_r c10_counter_rank.
qed.

lemma c10_embg_size (x : dgstblock * cntr) :
  size (c10_embg x) = 8 * n + c10_r.
proof.
  by rewrite /c10_embg size_cat DigestBlock.valP size_int2bs /c10_r; smt().
qed.

lemma c10_embg_constant_width (x y : dgstblock * cntr) :
  size (c10_embg x) = size (c10_embg y).
proof. by rewrite !c10_embg_size. qed.

(* INJECTIVITY, PROVED -- was previously PROSE ONLY.  Adversarial review
   (GPT-5.6, 2026-08-01) correctly observed that the comment above claimed the
   deployed serialisation "is injective" while the file proved only its WIDTH.
   That gap matters: the deployed capstone's premise is a statement about
   `size (emb_in witness)`, and a CONSTANT `emb_in` satisfies it while
   collapsing every ThC input and making the S-TCR term trivially winnable.
   `c10_embg` is literally `embg c10_r`, so the generic injectivity applies. *)
lemma c10_embg_is_embg : c10_embg = embg c10_r.
proof. by apply fun_ext => x; rewrite /c10_embg /embg. qed.

lemma c10_embg_inj (x y : dgstblock * cntr) :
  STCRC_WC.G.CntrFT.card <= 2 ^ c10_r =>
  c10_embg x = c10_embg y => x = y.
proof.
  move=> hcard; rewrite !c10_embg_is_embg => heq.
  by apply (embg_inj c10_r x y _ hcard heq); rewrite /c10_r.
qed.

lemma c10_emb_in_injective (x y : dgstblock * cntr) :
  emb_in x = emb_in y => x = y.
proof. by rewrite c10_emb_in_pinned; apply c10_embg_inj; exact c10_counter_cardinality_bound. qed.

lemma c10_emb_in_width (x : dgstblock * cntr) :
  size (emb_in x) = 8 * n + c10_r.
proof. by rewrite c10_emb_in_pinned c10_embg_size. qed.

(* Physical payload: 16 node bytes, 16 pad bytes, 28 pad bytes, 4 counter
   bytes. The two projections of ThC remain correlated halves of one digest;
   this adapter does not identify the abstract thfc operation with SHA-256. *)
op c10_payload (x : dgstblock * cntr) : int list =
  C10Bytes.payload (DigestBlock.val x.`1) x.`2.

lemma c10_payload_width (x : dgstblock * cntr) : size (c10_payload x) = 64.
proof. by rewrite /c10_payload C10Bytes.payload_size 1:DigestBlock.valP 1:n_val. qed.

lemma c10_payload_recovers_emb_in (x : dgstblock * cntr) :
  C10Bytes.bytes_to_bits (take 16 (c10_payload x)) ++
    C10Bytes.bytes_to_bits (drop 60 (c10_payload x)) = emb_in x.
proof.
  by rewrite /c10_payload /emb_in C10Bytes.payload_recovers_compact
    1:DigestBlock.valP 1:n_val.
qed.

lemma c10_payload_injective (x y : dgstblock * cntr) :
  c10_payload x = c10_payload y => x = y.
proof.
  move=> heq; apply c10_emb_in_injective.
  by rewrite -!c10_payload_recovers_emb_in heq.
qed.

(* So the deployed serialisation meets BOTH model requirements, not just one:
   constant width (LEN) and injectivity (INJ) -- the two premises that keep the
   S-TCR(+C) term a GENUINE second preimage rather than a collapse artefact. *)
lemma c10_embg_meets_LEN_and_INJ :
  STCRC_WC.G.CntrFT.card <= 2 ^ c10_r =>
     (forall (x y : dgstblock * cntr), size (c10_embg x) = size (c10_embg y))
  /\ (forall (x y : dgstblock * cntr), c10_embg x = c10_embg y => x = y).
proof.
  move=> hcard; split; first exact c10_embg_constant_width.
  by move=> x y; apply c10_embg_inj.
qed.

lemma c10_deployed_serialisation_meets_the_model :
  exists (g : dgstblock * cntr -> dgst),
       (forall x y, size (g x) = size (g y))
    /\ (forall x, size (g x) = 8 * n + c10_r).
proof.
  exists c10_embg; split.
  + exact c10_embg_constant_width.
  exact c10_embg_size.
qed.

(* -------------------------------------------------------------------------
   9.  THE DEPLOYED DIGIT MAP IS A LEGITIMATE ENCODER.

   sphincs-c10/src/wots.rs:16-46 extracts L base-w digits from the 32-byte
   wots_digest, digit i taken at bit offset i*LOG_W:
       digit i = (digest >> (i*LOG_W)) & W_MASK
   so digit i is the little-endian value of bits [3i, 3i+2], and the last digit
   (i = 42) reaches bit 128 -- 129 bits consumed out of 256.

   Modelled here as `c10_digit_at`, and shown to be a WELL-DEFINED base-w digit
   for every index and every input.  That is what `encode_msgWOTS` requires of
   an instantiation: since this fork retired both encoding axioms (P is a
   DEFINITION on the constant-sum surface, base-c10-split/WOTS_TW_ES.ec:617-644),
   well-definedness is the ONLY requirement, so the deployed map is admissible
   as `encode_msgWOTS`.
   ------------------------------------------------------------------------- *)
op c10_digit_at (bs : bool list) (i : int) : int =
  b2i (nth false bs (c10_log2_w * i))
  + 2 * b2i (nth false bs (c10_log2_w * i + 1))
  + 4 * b2i (nth false bs (c10_log2_w * i + 2)).

lemma c10_digit_at_ge0 (bs : bool list) (i : int) : 0 <= c10_digit_at bs i.
proof. by rewrite /c10_digit_at; smt(b2i_ge0). qed.

lemma c10_digit_at_lt_w (bs : bool list) (i : int) : c10_digit_at bs i < c10_w.
proof. by rewrite /c10_digit_at /c10_w; smt(b2i_le1 b2i_ge0). qed.

(* THE RECEIPT: every extracted digit is a valid base-w digit, at every index
   and on every input.  So the deployed extraction is admissible as the model's
   digit map -- which, since this fork retired both encoding axioms, is the ONLY
   requirement on an instantiation of `encode_msgWOTS`. *)
lemma c10_deployed_digit_map_is_wellformed (bs : bool list) (i : int) :
  0 <= c10_digit_at bs i < c10_w.
proof. by rewrite c10_digit_at_ge0 c10_digit_at_lt_w. qed.

(* The window the deployed extraction actually reads: L*LOG_W = 129 bits, which
   is why the message-digest width had to become its own parameter (129 > 8*16
   but 129 <= 8*32).  Recorded here so the three facts sit together. *)
lemma c10_window_bits : c10_len * c10_log2_w = 129.
proof. by rewrite /c10_len /c10_log2_w. qed.

lemma c10_window_fits_digest : c10_len * c10_log2_w <= 8 * c10_n_m.
proof. by rewrite c10_window_bits /c10_n_m. qed.

lemma c10_window_exceeds_chain_width : 8 * c10_n < c10_len * c10_log2_w.
proof. by rewrite c10_window_bits /c10_n. qed.

(* -------------------------------------------------------------------------
   10.  THE DEPLOYED DIGIT MAP ATTAINS 205.  (Residual Q2, geometric side.)

   An explicit 256-bit string whose low 129 bits, read by the deployed
   extraction, give 41 digits of 5 and 2 of 0 -- summing to exactly 205.
   Bit j is set iff j < 123 and j mod 3 <> 1, so each triple (3i, 3i+1, 3i+2)
   for i < 41 reads (1,0,1) little-endian = 1 + 0 + 4 = 5, and every triple from
   i = 41 on is all-zero.
   ------------------------------------------------------------------------- *)
op c10_witness_bits : bool list =
  mkseq (fun j => j < 123 /\ j %% 3 <> 1) (8 * c10_n_m).

lemma c10_witness_bit (j : int) :
  0 <= j < 8 * c10_n_m => nth false c10_witness_bits j = (j < 123 /\ j %% 3 <> 1).
proof. by move=> rng; rewrite /c10_witness_bits nth_mkseq. qed.

lemma c10_digit_lo (i : int) : 0 <= i < 41 => c10_digit_at c10_witness_bits i = 5.
proof.
  move=> rng; rewrite /c10_digit_at.
  rewrite !c10_witness_bit; 1..3: by rewrite /c10_log2_w /c10_n_m; smt().
  by rewrite /c10_log2_w /b2i; smt().
qed.

lemma c10_digit_hi (i : int) : 41 <= i < c10_len => c10_digit_at c10_witness_bits i = 0.
proof.
  move=> rng; move: rng; rewrite /c10_len => rng.
  rewrite /c10_digit_at.
  rewrite !c10_witness_bit; 1..3: by rewrite /c10_log2_w /c10_n_m; smt().
  by rewrite /c10_log2_w /b2i; smt().
qed.

(* THE STATEMENT: the DEPLOYED extraction, on an actual 256-bit input, produces
   digits summing to exactly the deployed TARGET_SUM. *)
lemma c10_deployed_encoder_attains_target :
  StdBigop.Bigint.BIA.bigi predT (c10_digit_at c10_witness_bits) 0 c10_len
  = c10_target_sum.
proof.
  rewrite /c10_target_sum.
  rewrite (StdBigop.Bigint.BIA.big_cat_int 41 0 c10_len) 1:// 1:/c10_len //.
  rewrite (StdBigop.Bigint.BIA.eq_big_int 0 41 _ (fun _ => 5)).
  + by move=> i hi /=; exact (c10_digit_lo i hi).
  rewrite (StdBigop.Bigint.BIA.eq_big_int 41 c10_len _ (fun _ => 0)).
  + by move=> i hi /=; exact (c10_digit_hi i hi).
  rewrite !StdBigop.Bigint.big_constz !count_predT !size_range /c10_len /=.
  by smt().
qed.

(* ==========================================================================
   TIER 0 (2026-08-02) — WIRE THE DEPLOYED SERIALISATION INTO THE MODEL.

   Everything above about `c10_embg` was PROVED AND CONSUMED BY NOTHING:
   `c10_embg_meets_LEN_and_INJ` had zero occurrences in the whole certified
   closure and `c10_embg_inj` fed only it -- a two-node orphan island.  Three
   adversarial rounds pointed at the consequence: the deployed capstone's only
   constraint on the encoder is `size (emb_in witness) = 8 * n + c10_r`, a
   statement about ONE POINT, which a CONSTANT `emb_in` satisfies while
   collapsing every ThC input and making the S-TCR(+C) term trivially winnable.

   These two lemmas close that by IDENTIFYING the abstract encoder with the
   deployed one.  Under `emb_in = c10_embg` the two model premises the S-TCR
   repair actually needs -- constant width (LEN) and injectivity (INJ) -- are
   THEOREMS, not assumptions, and the degenerate model is excluded rather than
   merely deprecated in a comment.

   WHAT THIS DOES NOT DO, stated so the header is not read as more: it bounds
   nothing.  The S-TCR term, Q, and the unreduced ITSRC10 term are untouched.

   [CORRECTED 2026-08-03, round 14, GPT-5.6 and Opus 5 INDEPENDENTLY.  This
   header used to end: "It changes the deployed statement from 'compatible with
   a model in which the scheme is broken' to 'conditional on the encoder being
   the deployed one'."  THAT IS FALSE.  `thfc` is declared with ZERO axioms
   (base-c10-split/SPHINCS_PLUS.ec:488) and `ThC` is DEFINED as two `thfc`
   applications (WOTS_C_Real.ec:213-215), so under `thfc := const` every ThC
   input still collapses and the S-TCR win condition's hard conjunct holds
   identically -- the tree says so itself at FORSC10_Wire.ec:77.  Pinning
   `emb_in` moved the collapse ONE COMPOSITION STEP; it did not remove it.
   AND WHAT IS PINNED IS NARROWER THAN "THE DEPLOYED ENCODER": `c10_embg`
   serialises the counter's RANK IN AN ARBITRARY ENUMERATION
   (`int2bs c10_r (index x.`2 CntrFT.enum)`), and `cntr` is an abstract FinType
   whose cardinality no axiom bounds.  A singleton counter satisfies every
   premise.  This is an INJECTIVE RANK ENCODER, not the firmware's u32.] 
   ========================================================================== *)
lemma c10_deployed_encoder_meets_model :
     STCRC_WC.G.CntrFT.card <= 2 ^ c10_r
  => emb_in = c10_embg
  =>    (forall (x y : dgstblock * cntr), size (emb_in x) = size (emb_in y))
     /\ (forall (x y : dgstblock * cntr), emb_in x = emb_in y => x = y).
proof.
  move=> hcard heq; rewrite heq.
  exact (c10_embg_meets_LEN_and_INJ hcard).
qed.

(* And the WIDTH premise the deployed capstone currently carries is itself a
   CONSEQUENCE of that identification -- so the single-point hypothesis need not
   be assumed separately once the encoder is pinned. *)
lemma c10_deployed_encoder_gives_width :
  emb_in = c10_embg => size (emb_in witness) = 8 * n + c10_r.
proof. by move=> heq; rewrite heq c10_embg_size. qed.
