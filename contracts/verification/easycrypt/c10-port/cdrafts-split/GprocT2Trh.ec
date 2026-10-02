(* T3 -- the TRCO reduction for Gproc.  SCRATCH: nothing integrates into the
   certified tree until a complete unit compiles.

   Port of R_TRCOSMDTTCRC_EUFCMA (base-c10-split/FORS_ES.ec:2643-2805) from
   MM45's multi-instance FORS game to C10's Gproc.  Substitutions:
     Adv_EUFCMA_MFORSTWESNPRF   -> Adv_EUFCMA_Gproc
     O_CMA_MFORSTWESNPRF_AV     -> O_CMA_Gproc_I
     trhtype                    -> trhftype        (the FTWES clone binds it)
     s, l                       -> nr_trees 0, l'  (likewise)
     g (mco mk' m')             -> M.F.hC mk' m'   (definitionally equal:
                                    FORS_C10.ec:211 is `hC mk m = g (mco mk m)`)
   The sk cube is sampled INLINE, mirroring GprocKg.keygen rather than MM45's
   gen_skFORS() call, so the two sides' loops align syntactically in the byequiv;
   GprocKg_sk_eq is the lemma that would otherwise have to bridge them. *)
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

(* ===========================================================================
   T2 -- the TRH branch of gproc_Q_decomposition:

     Pr[EUF_CMA_Gproc_V(A).main() :
          ((res /\ !covered) /\ !valid_OpenPRE) /\ valid_TRHTCR]
     <= Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(A), ..) : res]

   Port of MM45's R_TRHSMDTTCRC_EUFCMA (FORS_ES.ec:2448-2640) and its branch
   (FORS_ES.ec:4833-5943).  Same substitutions as T3:
     trhtype -> trhftype, s -> nr_trees 0, l -> l', nr_nodes -> nr_nodesf,
     g (mco mk m) -> M.F.hC mk m, and the sk cube sampled INLINE.

   THE ROLE SWAP vs T3.  In the TRCO reduction the whole tree (leaves AND
   interior nodes) went to the COLLECTION oracle OC and only the root
   concatenation was a challenge target.  Here it is the other way round: the
   leaves go to OC and every interior node is a CHALLENGE target on O.  So the
   invariants track the node layer, not the root row, and `find` returns a
   collision extracted from the forged authentication path rather than the
   root concatenation.
   =========================================================================== *)
module (R_TRH_Gproc (A : Adv_EUFCMA_Gproc) : FTWES.TRHC_TCR.Adv_SMDTTCRC)
       (O : FTWES.TRHC_TCR.Oracle_SMDTTCR, OC : FTWES.TRHC.Oracle_THFC) = {
  var ad : adrs
  var skFORSs : FTWES.skFORS list list
  var pkFORSs : FTWES.pkFORS list list

  proc pick() : unit = {
    var skFORS : FTWES.skFORS;
    var pkFORS : FTWES.pkFORS;
    var skFORSl : FTWES.skFORS list;
    var pkFORSl : FTWES.pkFORS list;
    var skFORS_ele, leaf, lnode, rnode, node : dgstblock;
    var skFORSet, leavest, nodespl, nodescl, rootsk : dgstblock list;
    var skFORScube, nodest : dgstblock list list;

    ad <- adz;
    skFORSs <- [];
    pkFORSs <- [];

    while (size skFORSs < nr_trees 0) {
      skFORSl <- [];
      pkFORSl <- [];

      while (size skFORSl < l') {
        skFORScube <- [];
        while (size skFORScube < k) {
          skFORSet <- [];
          while (size skFORSet < t) {
            skFORS_ele <$ ddgstblock;
            skFORSet <- rcons skFORSet skFORS_ele;
          }
          skFORScube <- rcons skFORScube skFORSet;
        }
        skFORS <- FTWES.DBLLKTL.insubd skFORScube;

        rootsk <- [];
        while (size rootsk < k) {
          (* leaves: COLLECTION oracle *)
          leavest <- [];
          while (size leavest < t) {
            leaf <@ OC.query(set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSs)) (size skFORSl))
                                         0 (size rootsk * t + size leavest),
                             DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skFORS) (size rootsk)) (size leavest)));
            leavest <- rcons leavest leaf;
          }

          (* interior nodes: CHALLENGE oracle -- the swap vs T3 *)
          nodest <- [];
          while (size nodest < a) {
            nodespl <- last leavest nodest;
            nodescl <- [];
            while (size nodescl < nr_nodesf (size nodest + 1)) {
              lnode <- nth witness nodespl (2 * size nodescl);
              rnode <- nth witness nodespl (2 * size nodescl + 1);
              node <@ O.query(set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSs)) (size skFORSl))
                                          (size nodest + 1) (size rootsk * nr_nodesf (size nodest + 1) + size nodescl),
                              DigestBlock.val lnode ++ DigestBlock.val rnode);
              nodescl <- rcons nodescl node;
            }
            nodest <- rcons nodest nodescl;
          }
          rootsk <- rcons rootsk (nth witness (nth witness nodest (a - 1)) 0);
        }

        (* the trco compression is a COLLECTION query here, not a challenge --
           in this reduction only the interior nodes are targets *)
        pkFORS <@ OC.query(set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSs)) (size skFORSl)) trcotype)
                                     (FTWES.get_kpidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSs)) (size skFORSl))),
                           flatten (map DigestBlock.val rootsk));

        skFORSl <- rcons skFORSl skFORS;
        pkFORSl <- rcons pkFORSl pkFORS;
      }
      skFORSs <- rcons skFORSs skFORSl;
      pkFORSs <- rcons pkFORSs pkFORSl;
    }
  }

  proc find(ps : pseed) : int * dgst = {
    var m' : msg;
    var mk' : mkey;
    var sig' : sigGproc;
    var sigFORSTW' : FTWES.sigFORSTW;
    var tidx, kpidx, hidx, bidx, dfidx, dftidx, dflfidx, cidx : int;
    var cm' : FTWES.msgFORSTW;
    var idx' : index;
    var x' : dgstblock;
    var ap' : FTWES.apFORSTW;
    var leaf' : dgstblock;
    var skFORSt, leaves : dgstblock list;
    var lidxs', cov : (int * int * int) list;
    var c : dgst;
    var cr : dgstblock * dgstblock * dgstblock * dgstblock * (int * int)
             * dgstblock bintree * dgstblock bintree * bool list;

    O_CMA_Gproc_I.init(skFORSs, ps, ad);

    (m', sig') <@ A(O_CMA_Gproc_I).forge((pkFORSs, ps, ad));

    (mk', sigFORSTW') <- sig';
    (cm', idx') <- FTWES.mco mk' m';
    lidxs' <- M.F.hC mk' m';
    cov    <- flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2)
                           O_CMA_Gproc_I.ts);
    (dfidx, dftidx, dflfidx) <- nth witness lidxs' (find (fun i => ! (i \in cov)) lidxs');
    (tidx, kpidx) <- edivz (Index.val idx') l';

    leaf' <- f ps (set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx) 0 (dftidx * t + dflfidx))
               (DigestBlock.val (nth witness (unzip1 (FTWES.DBAPKL.val sigFORSTW')) dftidx));

    skFORSt <- nth witness (FTWES.DBLLKTL.val (nth witness (nth witness skFORSs tidx) kpidx)) dftidx;
    leaves  <- mkseq (fun (i : int) =>
                 f ps (set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx) 0 (dftidx * t + i))
                   (DigestBlock.val (nth witness skFORSt i))) t;

    (x', ap') <- nth witness (FTWES.DBAPKL.val sigFORSTW') dftidx;

    cr <- FTWES.extract_collision_bt_ap_trh ps (set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx)
                                            (list2tree leaves) (FTWES.DBAL.val ap') (rev (int2bs a dflfidx))
                                            leaf' dftidx;
    c <- DigestBlock.val cr.`3 ++ DigestBlock.val cr.`4;
    (hidx, bidx) <- cr.`5;

    cidx <- tidx * l' * k * (2 ^ a - 1) + kpidx * k * (2 ^ a - 1) + dftidx * (2 ^ a - 1)
            + bigi predT (fun (i : int) => nr_nodesf i) 1 hidx + (bidx %% nr_nodesf hidx);

    return (cidx, c);
  }
}.

lemma adz_val : HA.Adrs.val adz = [0; 0; 0; chtype; 0; 0].
proof.
rewrite /adz HA.Adrs.insubdK //.
rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
left => @/valid_idxvalsch /=.
(* Deterministic, one condition at a time.  The blanket
     `smt(ge2_len ge2_lp expr_ge0 expr_gt0)`
   copied from SPHINCS_PLUS.ec:752 was TIMEOUT-MARGINAL: it passed on a quiet
   machine and turned this file RED under host CPU contention, with the failure
   reported at a line 800 lines above anything I had edited.  It also omitted
   `val_w` -- the `0 < w - 1` conjunct was being found by search, not by hint,
   which is exactly why it was fragile.  `val_w` lives in WOTS_TW_ES and is
   NOT in scope unqualified here (it is inside SPHINCS_PLUS.ec, where that
   idiom was copied from). *)
rewrite /valid_hidx /valid_chidx /valid_kpidx /valid_tidx /valid_lidx /nr_trees /=.
do ! split.
+ smt(WOTS_TW_ES.val_w).
+ smt(ge2_len).
+ smt(ge2_lp).
+ by rewrite expr_gt0.
smt(ge1_d).
qed.

op adzf : adrs = HA.Adrs.insubd [0; 0; 0; trhftype; 0; 0].

lemma valid_fidxvals_adzf : FTWES.valid_fidxvals [0; 0; 0; trhftype; 0; 0].
proof.
rewrite /valid_fidxvals /=.
(* `/=` already discharges valid_fidxvalsgp (drop 5 _): the clone binds it to
   `nth witness adidxs 0 = 0` (SPHINCS_PLUS.ec:537) and drop 5 _ = [0]. *)
left => @/valid_fidxvalslptrh /=.
rewrite /valid_tbfidx /valid_thfidx /valid_kpidx /valid_tidx /nr_nodesf /nr_trees /=.
smt(ge1_a ge1_k ge2_lp expr_gt0).
qed.

lemma valid_adrsidxs_adzf : valid_adrsidxs [0; 0; 0; trhftype; 0; 0].
proof.
rewrite /valid_adrsidxs /adrs_len /=.
by apply FTWES.valid_fidxvals_idxvals; exact valid_fidxvals_adzf.
qed.

lemma adzf_val : HA.Adrs.val adzf = [0; 0; 0; trhftype; 0; 0].
proof. by rewrite /adzf HA.Adrs.insubdK 1:valid_adrsidxs_adzf. qed.

lemma valid_fadrs_adzf : FTWES.valid_fadrs adzf.
proof.
by rewrite /valid_fadrs /valid_fadrsidxs adzf_val /adrs_len /= valid_fidxvals_adzf.
qed.

lemma settype_adz_adzf : set_typeidx adz trhftype = adzf.
proof. by rewrite /set_typeidx adz_val /adzf. qed.

lemma settype_adzf : set_typeidx adzf trhftype = adzf.
proof. by rewrite /set_typeidx adzf_val /adzf. qed.

(* The form actually used at the rewrite site.  MM45's lemmas are phrased over
   `set_typeidx ad trhtype`, so the goal has to be moved into that shape at
   ad := adzf -- not merely collapsed to adzf, which would no longer match. *)
lemma settype_adz_eq : set_typeidx adz trhftype = set_typeidx adzf trhftype.
proof. by rewrite settype_adz_adzf settype_adzf. qed.

(* The k-loop step's mathematical core, ISOLATED: a fully-built nodest whose
   entries are the val_bt_trh_gen values determines the root at layer a-1,
   position 0.  This is exactly the final step of GprocTreeVI_root_h, lifted out
   of that hoare so the TRCO branch can CITE it instead of re-deriving it inside
   a 19-hypothesis equiv goal -- which is where every in-place attempt stalled. *)
lemma root_from_nodest (psi : pseed) (adTi : adrs) (lfs : dgstblock list)
                       (ui : int) (ndst : dgstblock list list) :
     size ndst = a
  => (forall (u v : int), 0 <= u < size ndst => 0 <= v < nr_nodesf (u + 1) =>
        nth witness (nth witness ndst u) v
        = FTWES.val_bt_trh_gen psi adTi
            (oget (sub_bt (list2tree lfs) (rev (int2bs (a - u - 1) v)))) (u + 1)
            (ui * nr_nodesf (u + 1) + v))
  => nth witness (nth witness ndst (a - 1)) 0
     = FTWES.val_bt_trh psi adTi (list2tree lfs) ui.
proof.
move=> hsz hinv.
have h := hinv (a - 1) 0 _ _.
+ smt(ge1_a).
+ rewrite /nr_nodesf (: a - (a - 1 + 1) = 0) 1:/# expr0; smt().
move: h.
rewrite (: a - 1 + 1 = a) 1:/# (: a - (a - 1) - 1 = 0) 1:/#.
rewrite /nr_nodesf (: a - a = 0) 1:/# expr0 /=.
rewrite /int2bs mkseq0 rev_nil subbt_empty oget_some.
by rewrite /FTWES.val_bt_trh.
qed.

lemma node_level_step (psi : pseed) (adTi : adrs) (lfs : dgstblock list)
                      (ui : int) (ndst : dgstblock list list) (nc : int) :
     size lfs = t
  => 0 <= size ndst < a
  => (forall (u v : int), 0 <= u < size ndst => 0 <= v < nr_nodesf (u + 1) =>
        nth witness (nth witness ndst u) v
        = FTWES.val_bt_trh_gen psi adTi
            (oget (sub_bt (list2tree lfs) (rev (int2bs (a - u - 1) v)))) (u + 1)
            (ui * nr_nodesf (u + 1) + v))
  => 0 <= nc < nr_nodesf (size ndst + 1)
  => trh psi (set_thtbidx adTi (size ndst + 1) (ui * nr_nodesf (size ndst + 1) + nc))
         (DigestBlock.val (nth witness (last lfs ndst) (2 * nc))
          ++ DigestBlock.val (nth witness (last lfs ndst) (2 * nc + 1)))
     = FTWES.val_bt_trh_gen psi adTi
         (oget (sub_bt (list2tree lfs) (rev (int2bs (a - size ndst - 1) nc))))
         (size ndst + 1) (ui * nr_nodesf (size ndst + 1) + nc).
proof.
move=> eqt_szlfs [ge0_szndst lta_szndst] nthndst [ge0_nc ltnn1_nc].
rewrite /FTWES.val_bt_trh_gen (: a - size ndst - 1 = a - (size ndst + 1)) 1:/# /=.
rewrite subbt_list2tree_takedrop 4:oget_some; 1..3: smt(ge1_a size_ge0).
have ltnn_2nc1 : 2 * nc + 1 < nr_nodesf (size ndst).
- rewrite &(ltr_le_trans (2 + 2 * (nr_nodesf (size ndst + 1) - 1))) 1:/#.
  by rewrite /nr_nodesf mulzDr /= -{1}(expr1 2) -exprD_nneg // /#.
have ge1_2aszn2nc : 1 <= 2 ^ (a - size ndst) - 2 * nc - 1 by smt().
rewrite (last_nth witness); case (size ndst = 0) => [szn0 | nszn0].
- rewrite szn0 /= expr1 {3}(: 2 = 1 + 1) 1:// (take_nth witness) 1:size_drop 2:/=; 1,2: smt(size_ge0).
  rewrite (FTWES.take1_head witness) 1:size_drop 3:nth_drop 2:/= 4://; 1..3: smt(size_ge0).
  rewrite -cats1 (list2treeS 0) ?expr0 1..3:// /trhi /=.
  by rewrite ?list2tree1 /= -nth0_head nth_drop; smt(size_ge0).
rewrite nszn0 /= (: 2 ^ (size ndst + 1) = 2 ^ (size ndst) + 2 ^ (size ndst)).
+ by rewrite exprD_nneg 1:size_ge0 //= expr1 /#.
rewrite take_take_drop_cat 1,2:expr_ge0 1,2://.
rewrite drop_drop 1:expr_ge0 1://; 1: smt(expr_ge0).
rewrite (list2treeS (size ndst)) 1:size_ge0 1,2:size_take 1,3:expr_ge0 1,3:// 1,2:size_drop; 1,3: smt(size_ge0 expr_ge0).
+ rewrite eqt_szlfs /t (: 2 ^ a = 2 ^ (a - size ndst) * 2 ^ (size ndst)) 1:-exprD_nneg 2:size_ge0 1,2:/#.
  pose szn2 := 2 ^ (size ndst).
  rewrite (: 2 ^ (a - size ndst) * szn2 - nc * (szn2 + szn2) = (2 ^ (a - size ndst) - 2 * nc) * szn2) 1:/#.
  pose mx := max _ _; rewrite (: 2 ^ (size ndst) < mx) // /mx.
  pose sb := ((_ - _ * _) * _)%Int; rewrite &(ltr_le_trans sb) /sb 2:maxrr.
  by rewrite ltr_pmull 1:expr_gt0 // /#.
+ rewrite eqt_szlfs /t (: 2 ^ a = 2 ^ (a - size ndst) * 2 ^ (size ndst)) 1:-exprD_nneg 2:size_ge0 1,2:/#.
  pose szn2 := 2 ^ (size ndst).
  rewrite (: 2 ^ (a - size ndst) * szn2 - (szn2 + nc * (szn2 + szn2)) = (2 ^ (a - size ndst) - 2 * nc - 1) * szn2) 1:/#.
  pose sb := ((_ - _ - _) * _)%Int.
  move: ge1_2aszn2nc; rewrite lez_eqVlt => -[eq1_2as | gt1_2as].
  - by rewrite /sb -eq1_2as /= lez_maxr 1:expr_ge0.
  rewrite lez_maxr /sb 1:mulr_ge0 2:expr_ge0 //= 1:subr_ge0 1:ler_subr_addr.
  - rewrite &(ler_trans (1 + 2 * (nr_nodesf (size ndst + 1) - 1))) 1:/#.
    by rewrite /nr_nodesf mulzDr -{1}(expr1 2) -exprD_nneg // /#.
  rewrite (: szn2 < (2 ^ (a - size ndst) - 2 * nc - 1) * szn2) //.
  by rewrite ltr_pmull 1:expr_gt0.
rewrite 2?nthndst /=; 1..4: smt(size_ge0).
rewrite (: a - (size ndst - 1) - 1 = a - size ndst) 1:/#.
rewrite 2?subbt_list2tree_takedrop 3,6://; 1..4: smt(size_ge0).
rewrite oget_some /FTWES.val_bt_trh_gen /trhi /updhbidx /=; do 4! congr => [/# | /= | /# | /=].
+ rewrite /nr_nodesf mulrDr mulrA; congr.
  by rewrite eq_sym mulrAC -{1}(expr1 2) -exprD_nneg 1:// /#.
rewrite /nr_nodesf mulrDr -addrA; congr.
by rewrite eq_sym mulrCA; congr; rewrite -{1}(expr1 2) -exprD_nneg 1:// /#.
qed.

lemma gettype_nodeaddr (i j u v : int) :
     valid_tidx 0 i
  => valid_kpidx j
  => valid_thfidx u
  => valid_tbfidx u v
  => get_typeidx (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) u v)
     = trhftype.
proof.
move=> vi vj vu vv.
apply (FTWES.gettype_setthtbkptypetrh i j u v adz) => //.
+ by rewrite adz_val.
by rewrite adz_val /=; smt().
qed.

lemma gettype_leafaddr (i j v : int) :
     valid_tidx 0 i
  => valid_kpidx j
  => valid_thfidx 0
  => valid_tbfidx 0 v
  => get_typeidx (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 v)
     = trhftype.
proof.
move=> vi vj vu vv.
apply (FTWES.gettype_setthtbkptypetrh i j 0 v adz) => //.
+ by rewrite adz_val.
by rewrite adz_val /=; smt().
qed.

(* ---------------------------------------------------------------------------
   T2 helper layer.  The five-index ts address makes the invariants unreadable
   inline, so they are named.  These are DEFINITIONS -- they add no assumption.
   --------------------------------------------------------------------------- *)
(* NEW for TRH.  The ts entries must carry get_thidx <> 0 and the leaf
   collection queries get_thidx = 0 -- T3 never needed the height index because
   its targets were root compressions. *)
lemma getth_nodeaddr (i j u v : int) :
     valid_tidx 0 i => valid_kpidx j => valid_thfidx u => valid_tbfidx u v
  => FTWES.get_thidx (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) u v) = u.
proof.
move=> vi vj vu vv.
rewrite settype_adz_eq.
apply (FTWES.getth_setthtbkpttype i j u v adzf).
+ exact valid_fadrs_adzf.
+ exact vi.
+ exact vj.
+ exact vu.
exact vv.
qed.

lemma getth_leafaddr (i j v : int) :
     valid_tidx 0 i => valid_kpidx j => valid_thfidx 0 => valid_tbfidx 0 v
  => FTWES.get_thidx (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 v) = 0.
proof. by move=> vi vj vh vb; apply (getth_nodeaddr i j 0 v). qed.

(* ===========================================================================
   TWO-MODEL ADJUDICATION on T2's invariant debt (2026-08-06).  Both were asked
   independently; they CONVERGE on the structure and each adds one thing.

   CONVERGENT, and it is the load-bearing point: T3 is the WRONG TEMPLATE for
   the inner loops.  In T3, `ts` grew exactly ONCE per keypair (the trco
   challenge), so its INV-E/F/G/H carried ZERO ts conjuncts.  In T2, `ts` grows
   k*(2^a-1) entries per keypair, INSIDE the node loops.  So the k-loop, a-loop
   and nodescl-loop invariants must EACH carry the whole growing ts stack --
   otsdef with 3, 4 and 5 disjuncts respectively, the nth-characterisations
   layer by layer, uniq/all, and a PARTIAL-SUM size conjunct.  GPT-5.6 supplies
   exactly that as t2_memA..E / t2_nthA..E; Kimi names it as the miss T3's shape
   actively trains you to make, and notes the k-loop exit has nothing to fold
   the current tree's entries FROM if the inner invariants are T3-shaped.  This
   is the TRH analogue of the missing-otsdef defect, four conjuncts deep.

   BOTH also warn, independently, AGAINST porting T3's rsdef analogue here:
   TRH keeps ={rootsk} directly, and GprocVI materialises MM45's find as ghost
   state (GprocVI.ec:343-344) computing valid_TRHTCR single-shot, so there is no
   roots loop to align.  Adding it manufactures a spurious root_from_nodest
   obligation.  Left to myself I would have transcribed it by analogy.

   KIMI ONLY, and it is about the SUFFIX, so record it before getting there:
   the conseq premise must retain BOTH `valid_TRHTCR` (path verifies => eqout)
   AND `! valid_OpenPRE` (leaf diverges => x <> x').  In T3 the single
   load-bearing flag was !valid_TRHTCR; here it takes two, and dropping either
   leaves the final goal unclosable.

   GPT-5.6 ONLY: node_level_step needs no TRH variant (inlining O.query exposes
   the same trh computation) -- I had assumed it would.
   =========================================================================== *)

(* NEW for TRH: the CHALLENGE INPUT.  node_level_step (lifted from T3) says what
   the node loop RETURNS; this says what it QUERIES -- the concatenation of the
   two children, expressed at layer (size ndst) so it matches the ts entry's
   second component.  T3 needed no such lemma because its challenge input was a
   root concatenation, not a sibling pair. *)
lemma node_children_step (psi : pseed) (adTi : adrs) (lfs : dgstblock list)
                         (ui : int) (ndst : dgstblock list list) (nc : int) :
     size lfs = t
  => 0 <= size ndst < a
  => (forall (u v : int), 0 <= u < size ndst => 0 <= v < nr_nodesf (u + 1) =>
        nth witness (nth witness ndst u) v
        = FTWES.val_bt_trh_gen psi adTi
            (oget (sub_bt (list2tree lfs) (rev (int2bs (a - u - 1) v)))) (u + 1)
            (ui * nr_nodesf (u + 1) + v))
  => 0 <= nc < nr_nodesf (size ndst + 1)
  => DigestBlock.val (nth witness (last lfs ndst) (2 * nc))
     ++ DigestBlock.val (nth witness (last lfs ndst) (2 * nc + 1))
     = DigestBlock.val (FTWES.val_bt_trh_gen psi adTi
         (oget (sub_bt (list2tree lfs) (rev (int2bs (a - size ndst) (2 * nc)))))
         (size ndst) (ui * nr_nodesf (size ndst) + 2 * nc))
       ++
       DigestBlock.val (FTWES.val_bt_trh_gen psi adTi
         (oget (sub_bt (list2tree lfs) (rev (int2bs (a - size ndst) (2 * nc + 1)))))
         (size ndst) (ui * nr_nodesf (size ndst) + 2 * nc + 1)).
proof.
move=> eqt_szlfs [ge0_szndst lta_szndst] nthndst [ge0_nc ltnn1_nc].
have rngch : 0 <= 2 * nc + 1 < nr_nodesf (size ndst).
+ split => [| _]; 1: smt(size_ge0).
  rewrite (IntOrder.ler_lt_trans (nr_nodesf (size ndst) - 1)) 2:/#.
  rewrite (: nr_nodesf (size ndst) = 2 * nr_nodesf (size ndst + 1)) 2:/#.
  by rewrite -(expr1 2) /nr_nodesf -exprD_nneg 1:// 1,2:/#.
rewrite -nth_last.
case (size ndst = 0) => [eq0_sznds | neq0_sznds].
+ rewrite eq0_sznds /= (nth_out _ _ (-1)) 1://.
  have eq2a_szlfs : size lfs = 2 ^ a by rewrite eqt_szlfs /t.
  have hs0 : sub_bt (list2tree lfs) (rev (int2bs a (2 * nc)))
             = Some (Leaf (nth witness lfs (2 * nc))).
  - apply (subbt_list2tree_idx_leaf witness lfs (2 * nc) a).
    + smt(ge1_a).
    + exact eq2a_szlfs.
    move: rngch; rewrite eq0_sznds /nr_nodesf /= -/t -eqt_szlfs => /#.
  have hs1 : sub_bt (list2tree lfs) (rev (int2bs a (2 * nc + 1)))
             = Some (Leaf (nth witness lfs (2 * nc + 1))).
  - apply (subbt_list2tree_idx_leaf witness lfs (2 * nc + 1) a).
    + smt(ge1_a).
    + exact eq2a_szlfs.
    move: rngch; rewrite eq0_sznds /nr_nodesf /= -/t -eqt_szlfs => /#.
  by rewrite hs0 hs1 /= /FTWES.val_bt_trh_gen.
rewrite -(nth_change_dfl lfs witness); 1: smt(size_ge0).
by rewrite ?nthndst /= 4://; smt(size_ge0).
qed.

op t2_span : int = 2 ^ a - 1.

op t2_off (i j u v w : int) : int =
  i * l' * k * t2_span + j * k * t2_span + u * t2_span
  + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w.

op t2_adT (ad0 : adrs) (i j : int) : adrs =
  set_kpidx (set_tidx (set_typeidx ad0 trhftype) i) j.

op t2_pre (psi : pseed) (adT : adrs) (lvs : dgstblock list)
          (u v w : int) : dgst =
  DigestBlock.val (FTWES.val_bt_trh_gen psi adT
    (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w))))) v
    (u * nr_nodesf v + 2 * w))
  ++
  DigestBlock.val (FTWES.val_bt_trh_gen psi adT
    (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w + 1))))) v
    (u * nr_nodesf v + 2 * w + 1)).

op t2_entry_lvs (ad0 : adrs) (psi : pseed) (lvs : dgstblock list)
                (i j u v w : int) : adrs * dgst =
  (set_thtbidx (t2_adT ad0 i j) (v + 1) (u * nr_nodesf (v + 1) + w),
   t2_pre psi (t2_adT ad0 i j) lvs u v w).

op t2_entry_sk (ad0 : adrs) (psi : pseed) (skF : FTWES.skFORS)
               (i j u v w : int) : adrs * dgst =
  t2_entry_lvs ad0 psi (fors_leaves_op_cube skF psi (t2_adT ad0 i j) u) i j u v w.

op t2_nodeval (psi : pseed) (adT : adrs) (lvs : dgstblock list)
              (u v w : int) : dgstblock =
  FTWES.val_bt_trh_gen psi adT
    (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v - 1) w))))
    (v + 1) (u * nr_nodesf (v + 1) + w).

op t2_memA (ts : (adrs * dgst) list) (si : int) (adx : adrs * dgst) : bool =
  exists (i j u v w : int),
    0 <= i < si /\ 0 <= j < l' /\ 0 <= u < k /\
    0 <= v < a /\ 0 <= w < nr_nodesf (v + 1) /\
    adx = nth witness ts (t2_off i j u v w).

op t2_memB (ts : (adrs * dgst) list) (si ji : int) (adx : adrs * dgst) : bool =
  exists (j u v w : int),
    0 <= j < ji /\ 0 <= u < k /\ 0 <= v < a /\
    0 <= w < nr_nodesf (v + 1) /\ adx = nth witness ts (t2_off si j u v w).

op t2_memC (ts : (adrs * dgst) list) (si ji ui : int) (adx : adrs * dgst) : bool =
  exists (u v w : int),
    0 <= u < ui /\ 0 <= v < a /\ 0 <= w < nr_nodesf (v + 1) /\
    adx = nth witness ts (t2_off si ji u v w).

op t2_memD (ts : (adrs * dgst) list) (si ji ui vi : int) (adx : adrs * dgst) : bool =
  exists (v w : int),
    0 <= v < vi /\ 0 <= w < nr_nodesf (v + 1) /\
    adx = nth witness ts (t2_off si ji ui v w).

op t2_memE (ts : (adrs * dgst) list) (si ji ui vi wi : int) (adx : adrs * dgst) : bool =
  exists (w : int), 0 <= w < wi /\ adx = nth witness ts (t2_off si ji ui vi w).

op t2_nthA (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
           (sks : FTWES.skFORS list list) (si : int) : bool =
  forall (i j u v w : int),
    0 <= i < si => 0 <= j < l' => 0 <= u < k =>
    0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
    nth witness ts (t2_off i j u v w)
    = t2_entry_sk ad0 psi (nth witness (nth witness sks i) j) i j u v w.

op t2_nthB (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
           (skl : FTWES.skFORS list) (si ji : int) : bool =
  forall (j u v w : int),
    0 <= j < ji => 0 <= u < k => 0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
    nth witness ts (t2_off si j u v w)
    = t2_entry_sk ad0 psi (nth witness skl j) si j u v w.

op t2_nthC (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
           (skF : FTWES.skFORS) (si ji ui : int) : bool =
  forall (u v w : int),
    0 <= u < ui => 0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
    nth witness ts (t2_off si ji u v w) = t2_entry_sk ad0 psi skF si ji u v w.

op t2_nthD (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
           (lvs : dgstblock list) (si ji ui vi : int) : bool =
  forall (v w : int),
    0 <= v < vi => 0 <= w < nr_nodesf (v + 1) =>
    nth witness ts (t2_off si ji ui v w) = t2_entry_lvs ad0 psi lvs si ji ui v w.

op t2_nthE (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
           (lvs : dgstblock list) (si ji ui vi wi : int) : bool =
  forall (w : int),
    0 <= w < wi =>
    nth witness ts (t2_off si ji ui vi w) = t2_entry_lvs ad0 psi lvs si ji ui vi w.

op t2_ndst (psi : pseed) (adT : adrs) (lvs : dgstblock list)
           (ui : int) (ndst : dgstblock list list) : bool =
  forall (v w : int),
    0 <= v < size ndst => 0 <= w < nr_nodesf (v + 1) =>
    nth witness (nth witness ndst v) w = t2_nodeval psi adT lvs ui v w.

op t2_ndscl (psi : pseed) (adT : adrs) (lvs : dgstblock list)
            (ui vi : int) (ndscl : dgstblock list) : bool =
  forall (w : int),
    0 <= w < size ndscl => nth witness ndscl w = t2_nodeval psi adT lvs ui vi w.

(* CHECKED AT THE SOURCE, 2026-08-06, because it was raised as a possible defect
   in t2_good: leaf addresses sit at LAYER 0, so `get_thidx <> 0` would be FALSE
   for them, and if leaf queries landed in `ts` this predicate would be wrong as
   stated and every invariant carrying it would need revising.

   They do not.  Reading R_TRH_Gproc itself rather than reasoning about it:
     leaf  <@ OC.query(... 0 (size rootsk * t + size leavest), ...)   <- COLLECTION
     node  <@ O.query (... (size nodest + 1) (...), ...)              <- CHALLENGE
     pkFORS<@ OC.query(... trcotype ...)                              <- COLLECTION
   So `ts` receives ONLY node addresses, every one at layer size nodest + 1 >= 1,
   and the leaf and trco addresses go to `tws`, whose predicate is the
   `trcotype \/ get_thidx = 0` disjunction that exactly admits them.  t2_good is
   correct as written.

   Worth recording for the leaf loop, which is next: it does NOT touch `ts` at
   all.  Its invariant carries the ts stack UNCHANGED at memA/memB/memC depth
   (nodest is still empty there), and only `leavest` and `tws` move. *)
op t2_good (ts : (adrs * dgst) list) (tws : adrs list) : bool =
     uniq (unzip1 ts)
  /\ all (fun ad => get_typeidx ad = trhftype /\ FTWES.get_thidx ad <> 0) (unzip1 ts)
  /\ all (fun ad => get_typeidx ad = trcotype \/ FTWES.get_thidx ad = 0) tws.

(* --------------------------------------------------------------------------
   STEP 1: the node index stays inside its tree's span.

   This is the well-formedness fact the whole flat layout rests on: within one
   FORS tree, the layer-major index `bigi nr_nodesf 1 (v+1) + w` is < 2^a - 1 =
   t2_span.  Without it, t2_off's blocks overlap and every nth-preservation
   argument in the node body is false.

   MM45 already prove exactly this as ltnn1_bignna (FORS_ES.ec:788) -- cite it
   rather than reprove.  (This is also why `sum_nr_nodesf` was not worth
   grinding on: the fact we actually need was already packaged.) *)
lemma t2_idx_lt_span (v w : int) :
     0 <= v < a
  => 0 <= w < nr_nodesf (v + 1)
  => bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w < t2_span.
proof.
move=> hv hw; rewrite /t2_span.
by apply FTWES.ltnn1_bignna.
qed.

(* --------------------------------------------------------------------------
   STEP 2: t2_off is strictly increasing in the lexicographic order the loops
   traverse.  This is what makes `nth (rcons ts y) idx = nth ts idx` hold for
   every ALREADY-COMMITTED index -- i.e. what preserves t2_nthA..E across the
   node body's append.  GPT-5.6 flagged a helper of this shape as the thing
   that would remove the largest remaining boilerplate; these are it. *)
lemma t2_off_mono_w (si ji ui vi w w' : int) :
  w < w' => t2_off si ji ui vi w < t2_off si ji ui vi w'.
proof. by rewrite /t2_off => /#. qed.

lemma bigi_nnf_ge0 (x y : int) :
  0 <= bigi predT (fun (m : int) => nr_nodesf m) x y.
proof. by rewrite sumr_ge0 => ? _ /=; rewrite /nr_nodesf expr_ge0. qed.

lemma t2_off_mono_v (si ji ui v w vi wi : int) :
     0 <= v < vi
  => 0 <= w < nr_nodesf (v + 1)
  => 0 <= wi
  => t2_off si ji ui v w < t2_off si ji ui vi wi.
proof.
move=> [ge0_v ltvi_v] [ge0_w ltnn_w] ge0_wi.
have key : bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w
           < bigi predT (fun (m : int) => nr_nodesf m) 1 (vi + 1).
+ rewrite (: bigi predT (fun (m : int) => nr_nodesf m) 1 (vi + 1)
             = bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 2)
               + bigi predT (fun (m : int) => nr_nodesf m) (v + 2) (vi + 1)).
  - by rewrite -big_cat_int 1,2:/#.
  rewrite (big_int_recr (v+1)) 1:/# /=.
  smt(bigi_nnf_ge0).
by rewrite /t2_off; smt().
qed.

(* --------------------------------------------------------------------------
   STEP 3: the append itself.  The node body writes ONE entry, at index exactly
   `size ts`, and every already-committed entry must survive.  Both halves come
   straight from the ordering above. *)
lemma t2_nthE_append (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                     (lvs : dgstblock list) (si ji ui vi wi : int) :
     size ts = t2_off si ji ui vi wi
  => 0 <= wi
  => t2_nthE ts ad0 psi lvs si ji ui vi wi
  => t2_nthE (rcons ts (t2_entry_lvs ad0 psi lvs si ji ui vi wi))
             ad0 psi lvs si ji ui vi (wi + 1).
proof.
move=> hsz ge0_wi hE w [ge0_w ltw].
rewrite nth_rcons hsz.
case (w < wi) => [ltwi_w | gewi_w].
+ rewrite (: t2_off si ji ui vi w < t2_off si ji ui vi wi) 1:t2_off_mono_w 1:// /=.
  by apply hE.
have -> : w = wi by smt().
by rewrite /= .
qed.

(* Cross-TREE, cross-KEYPAIR and cross-INSTANCE ordering.  Each rides on
   t2_idx_lt_span: a whole tree's worth of node indices fits inside one
   t2_span block, so a strictly earlier u / j / i is strictly earlier in the
   flat layout regardless of where inside its own block it sits. *)
lemma t2_off_mono_u (si ji u v w ui vi wi : int) :
     0 <= u < ui
  => 0 <= v < a => 0 <= w < nr_nodesf (v + 1)
  => 0 <= vi < a => 0 <= wi
  => t2_off si ji u v w < t2_off si ji ui vi wi.
proof.
move=> [ge0_u ltui_u] hv hw hvi ge0_wi.
have hin := t2_idx_lt_span v w hv hw.
rewrite /t2_off.
have ge1_span : 1 <= t2_span by rewrite /t2_span -/t; smt(ge2_t).
smt(bigi_nnf_ge0).
qed.

lemma t2_off_mono_j (si j u v w ji ui vi wi : int) :
     0 <= j < ji
  => 0 <= u < k => 0 <= v < a => 0 <= w < nr_nodesf (v + 1)
  => 0 <= ui < k => 0 <= vi < a => 0 <= wi
  => t2_off si j u v w < t2_off si ji ui vi wi.
proof.
move=> [ge0_j ltji_j] [ge0_u ltk_u] hv hw [ge0_ui ltk_ui] hvi ge0_wi.
have hin := t2_idx_lt_span v w hv hw.
rewrite /t2_off.
have ge1_span : 1 <= t2_span by rewrite /t2_span -/t; smt(ge2_t).
have hlt : u * t2_span
             + (bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
           < k * t2_span.
+ have : u * t2_span + t2_span <= k * t2_span by smt().
  smt().
have hge : 0 <= ui * t2_span
             + (bigi predT (fun (m : int) => nr_nodesf m) 1 (vi + 1) + wi).
+ smt(bigi_nnf_ge0).
have hk : 0 <= k * t2_span by smt(ge1_k).
have hstep : (j + 1) * (k * t2_span) <= ji * (k * t2_span).
+ by rewrite ler_pmul2r 1:/# /#.
by rewrite -!mulrA; smt().
qed.

(* Cross-INSTANCE, completing the ordering.  Same shape as the keypair case
   one level up: a whole instance's node indices fit in l'*k*t2_span. *)
lemma t2_off_mono_i (i j u v w si ji ui vi wi : int) :
     0 <= i < si
  => 0 <= j < l' => 0 <= u < k => 0 <= v < a => 0 <= w < nr_nodesf (v + 1)
  => 0 <= ji < l' => 0 <= ui < k => 0 <= vi < a => 0 <= wi
  => t2_off i j u v w < t2_off si ji ui vi wi.
proof.
move=> [ge0_i ltsi_i] [ge0_j ltl_j] [ge0_u ltk_u] hv hw
       [ge0_ji ltl_ji] [ge0_ui ltk_ui] hvi ge0_wi.
have hin := t2_idx_lt_span v w hv hw.
have ge1_span : 1 <= t2_span by rewrite /t2_span -/t; smt(ge2_t).
rewrite /t2_off.
have hlt : j * k * t2_span + u * t2_span
             + (bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
           < l' * k * t2_span.
+ have hj : (j + 1) * (k * t2_span) <= l' * (k * t2_span).
  - by rewrite ler_pmul2r 1:/# /#.
  have hu : (u + 1) * t2_span <= k * t2_span.
  - by rewrite ler_pmul2r 1:/# /#.
  by rewrite -!mulrA; smt().
have hge : 0 <= ji * k * t2_span + ui * t2_span
             + (bigi predT (fun (m : int) => nr_nodesf m) 1 (vi + 1) + wi).
+ smt(bigi_nnf_ge0 ge1_k ge2_lp).
have hstep : (i + 1) * (l' * k * t2_span) <= si * (l' * k * t2_span).
+ by rewrite ler_pmul2r 1:/# /#.
by rewrite -!mulrA; smt().
qed.

(* --------------------------------------------------------------------------
   STEP 4: the earlier layers survive the append.  Each is the same argument --
   every committed index is < size ts, so nth_rcons returns the old entry --
   differing only in which monotonicity lemma supplies "<". *)
lemma t2_nthD_append (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                     (lvs : dgstblock list) (si ji ui vi wi : int) (y : adrs * dgst) :
     size ts = t2_off si ji ui vi wi
  => 0 <= vi < a
  => 0 <= wi
  => t2_nthD ts ad0 psi lvs si ji ui vi
  => t2_nthD (rcons ts y) ad0 psi lvs si ji ui vi.
proof.
move=> hsz hvi ge0_wi hD v w hv hw.
rewrite nth_rcons hsz.
rewrite (: t2_off si ji ui v w < t2_off si ji ui vi wi) 1:t2_off_mono_v 1..3:// /=.
by apply hD.
qed.

lemma t2_nthC_append (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                     (skF : FTWES.skFORS) (si ji ui vi wi : int) (y : adrs * dgst) :
     size ts = t2_off si ji ui vi wi
  => 0 <= vi < a
  => 0 <= wi
  => t2_nthC ts ad0 psi skF si ji ui
  => t2_nthC (rcons ts y) ad0 psi skF si ji ui.
proof.
move=> hsz hvi ge0_wi hC u v w hu hv hw.
rewrite nth_rcons hsz.
rewrite (: t2_off si ji u v w < t2_off si ji ui vi wi)
        1:(t2_off_mono_u si ji u v w ui vi wi hu hv hw hvi ge0_wi) /=.
by apply hC.
qed.

lemma t2_nthB_append (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                     (skl : FTWES.skFORS list) (si ji ui vi wi : int) (y : adrs * dgst) :
     size ts = t2_off si ji ui vi wi
  => 0 <= ui < k => 0 <= vi < a => 0 <= wi
  => t2_nthB ts ad0 psi skl si ji
  => t2_nthB (rcons ts y) ad0 psi skl si ji.
proof.
move=> hsz hui hvi ge0_wi hB j u v w hj hu hv hw.
rewrite nth_rcons hsz.
rewrite (: t2_off si j u v w < t2_off si ji ui vi wi)
        1:(t2_off_mono_j si j u v w ji ui vi wi hj hu hv hw hui hvi ge0_wi) /=.
by apply hB.
qed.

lemma t2_nthA_append (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                     (sks : FTWES.skFORS list list) (si ji ui vi wi : int) (y : adrs * dgst) :
     size ts = t2_off si ji ui vi wi
  => 0 <= ji < l' => 0 <= ui < k => 0 <= vi < a => 0 <= wi
  => t2_nthA ts ad0 psi sks si
  => t2_nthA (rcons ts y) ad0 psi sks si.
proof.
move=> hsz hji hui hvi ge0_wi hA i j u v w hi hj hu hv hw.
rewrite nth_rcons hsz.
rewrite (: t2_off i j u v w < t2_off si ji ui vi wi)
        1:(t2_off_mono_i i j u v w si ji ui vi wi hi hj hu hv hw hji hui hvi ge0_wi) /=.
by apply hA.
qed.

(* --------------------------------------------------------------------------
   STEP 5: node addresses at distinct coordinates are distinct.

   This is the "largest remaining boilerplate" GPT-5.6 identified: MM45 have
   four separate neq*_setthtbkpt lemmas, one per differing coordinate, each
   yielding a differing INDEX POSITION rather than an address inequality.
   Packaging them once, through adzf (they all require valid_fadrs, which our
   chain-rooted adz does not satisfy), turns every freshness obligation in the
   node body into a single citation. *)
lemma nodeaddr_neq (i j u v i' j' u' v' : int) :
     valid_tidx 0 i => valid_kpidx j => valid_thfidx u => valid_tbfidx u v
  => valid_tidx 0 i' => valid_kpidx j' => valid_thfidx u' => valid_tbfidx u' v'
  => (i <> i' \/ j <> j' \/ u <> u' \/ v <> v')
  => set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) u v
     <> set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i') j') u' v'.
proof.
move=> vi vj vu vv vi' vj' vu' vv' hne.
rewrite settype_adz_eq -HA.eq_adrs_idxs.
case: hne => [ne | [ne | [ne | ne]]].
+ apply (neq_from_nth witness _ _ 4).
  by apply (FTWES.neqtidx_setthtbkpt i i' j j' u u' v v' adzf valid_fadrs_adzf).
+ apply (neq_from_nth witness _ _ 2).
  by apply (FTWES.neqkpidx_setthtbkpt i i' j j' u u' v v' adzf valid_fadrs_adzf).
+ apply (neq_from_nth witness _ _ 1).
  by apply (FTWES.neqthidx_setthtbkpt i i' j j' u u' v v' adzf valid_fadrs_adzf).
apply (neq_from_nth witness _ _ 0).
by apply (FTWES.neqtbidx_setthtbkpt i i' j j' u u' v v' adzf valid_fadrs_adzf).
qed.

(* --------------------------------------------------------------------------
   STEP 6: the breadth index is injective in (tree, node).

   A ts address packs BOTH the tree index u and the within-layer position w into
   one breadth field, u * nr_nodesf (v+1) + w.  So two entries at the same layer
   collide iff that packed value collides -- and it does not, because
   w < nr_nodesf (v+1) makes the encoding a division with remainder.  Without
   this, freshness would be false as stated: distinct (u,w) could name the same
   address. *)
lemma tbidx_inj (u w u' w' vi : int) :
     0 <= w < nr_nodesf (vi + 1)
  => 0 <= w' < nr_nodesf (vi + 1)
  => u * nr_nodesf (vi + 1) + w = u' * nr_nodesf (vi + 1) + w'
  => u = u' /\ w = w'.
proof.
move=> [ge0_w ltw] [ge0_w' ltw'] heq.
have gt0_nn : 0 < nr_nodesf (vi + 1) by rewrite /nr_nodesf expr_gt0.
have hu : u = u'.
+ have -> : u = (u * nr_nodesf (vi + 1) + w) %/ nr_nodesf (vi + 1).
  - by rewrite divzMDl 1:/# pdiv_small 1:// /#.
  rewrite heq divzMDl 1:/# pdiv_small 1:// /#.
smt().
qed.

(* --------------------------------------------------------------------------
   STEP 7: FRESHNESS.  A node address at a strictly-earlier coordinate tuple
   differs from the one about to be appended.  This is what discharges the uniq
   half of t2_good in the node body.

   The case analysis is the whole content: if i, j or the LAYER differ,
   nodeaddr_neq applies directly; if all three agree, then (u,w) must differ,
   and tbidx_inj turns that into differing PACKED BREADTH -- which is
   nodeaddr_neq's fourth disjunct.  Skipping the last case is how one would
   "prove" freshness while it is actually false. *)
lemma nodeaddr_fresh (i j u v w si ji ui vi wi : int) :
     valid_tidx 0 i => valid_kpidx j
  => valid_thfidx (v + 1) => valid_tbfidx (v + 1) (u * nr_nodesf (v + 1) + w)
  => valid_tidx 0 si => valid_kpidx ji
  => valid_thfidx (vi + 1) => valid_tbfidx (vi + 1) (ui * nr_nodesf (vi + 1) + wi)
  => 0 <= w < nr_nodesf (v + 1)
  => 0 <= wi < nr_nodesf (vi + 1)
  => (i <> si \/ j <> ji \/ u <> ui \/ v <> vi \/ w <> wi)
  => set_thtbidx (t2_adT adz i j) (v + 1) (u * nr_nodesf (v + 1) + w)
     <> set_thtbidx (t2_adT adz si ji) (vi + 1) (ui * nr_nodesf (vi + 1) + wi).
proof.
move=> vi_ vj_ vu_ vv_ vsi_ vji_ vui_ vvi_ hw hwi hne.
rewrite /t2_adT.
apply (nodeaddr_neq i j (v + 1) (u * nr_nodesf (v + 1) + w)
                    si ji (vi + 1) (ui * nr_nodesf (vi + 1) + wi)) => //.
case (i <> si) => [nei | eqi]; 1: by left.
case (j <> ji) => [nej | eqj]; 1: by right; left.
case (v <> vi) => [nev | eqv]; 1: by right; right; left; smt().
right; right; right.
have hne2 : u <> ui \/ w <> wi by smt().
have eqv' : v = vi by smt().
move: hw hne2; rewrite eqv' => hw hne2.
by have := tbidx_inj u w ui wi vi hw hwi; smt().
qed.

(* --------------------------------------------------------------------------
   STEP 8: the OTSDEF (membership) update.

   FOUND BY ADVERSARIAL REVIEW (Kimi K3, 2026-08-06), and it is the gap the
   other reviewer missed.  The t2_nth*_append family updates the INDEXED
   characterisations; nothing here touched the t2_mem* disjuncts at all.  MM45
   spend FORS_ES.ec:5443-5545 -- roughly half their node body, more lines than
   the freshness argument -- on exactly this membership iff.  "30 lemmas, 0
   admits" covered the nth half and the freshness half and silently omitted the
   third.

   Both directions reduce to nth_rcons plus the ordering already proved:
   forwards, an old member sits at an index < size ts so rcons does not move it;
   backwards, the new index IS size ts. *)
lemma t2_memE_new (ts : (adrs * dgst) list) (si ji ui vi wi : int) (y : adrs * dgst) :
     size ts = t2_off si ji ui vi wi
  => 0 <= wi
  => t2_memE (rcons ts y) si ji ui vi (wi + 1) y.
proof.
move=> hsz ge0_wi; rewrite /t2_memE; exists wi.
by rewrite -hsz nth_rcons /=; smt().
qed.

lemma t2_memE_old (ts : (adrs * dgst) list) (si ji ui vi wi : int)
                  (y adx : adrs * dgst) :
     size ts = t2_off si ji ui vi wi
  => 0 <= wi
  => t2_memE ts si ji ui vi wi adx
  => t2_memE (rcons ts y) si ji ui vi (wi + 1) adx.
proof.
move=> hsz ge0_wi [w] [[ge0_w ltw] ->]; exists w.
rewrite ge0_w /= nth_rcons hsz.
by rewrite (: t2_off si ji ui vi w < t2_off si ji ui vi wi) 1:t2_off_mono_w 1:// /#.
qed.

(* --------------------------------------------------------------------------
   STEP 9: the FULL-LAYER SUM.

   RETRACTION.  I earlier dropped this as "useful, not essential", on the ground
   that MM45 already package what we need as ltnn1_bignna.  Adversarial review
   (GPT-5.6) showed that is wrong: ltnn1_bignna gives a strict PREFIX bound
   (bigi 1 (v+1) + w < 2^a - 1), and the a-loop EXIT needs the EQUALITY
   bigi 1 (a+1) = 2^a - 1 to fold a completed tree's layers into one t2_span.
   A bound cannot prove an equality.  MM45 derive it explicitly at
   FORS_ES.ec:5714.  It is on the critical path and dropping it was a mistake. *)
lemma sum_nr_nodesf :
  bigi predT (fun (m : int) => nr_nodesf m) 1 (a + 1) = t2_span.
proof.
rewrite /t2_span.
rewrite eq_sym /nr_nodesf.
have ge0_a : 0 <= a by smt(ge1_a).
rewrite (big_reindex _ _ (fun i => a - i) (fun i => a - i)).
+ by move=> i /mem_range rng_i /= /#.
rewrite /(\o) /predT /= -/predT (eq_bigr _ _ (fun i => 2 ^ i)).
+ by move=> i _ /=; congr; ring.
rewrite (eq_big_perm _ _ _ (range 0 a)).
+ rewrite uniq_perm_eq_size 2:range_uniq 2:size_map 2:?size_range 2://.
  - by rewrite map_inj_in_uniq 2:range_uniq => i j rng_i rng_j /= /#.
  by move=> i /mapP [j] [/mem_range rng_j /= ->]; rewrite mem_range; smt(ge1_a).
elim: a ge0_a => [| i ge0_i ih]; 1: by rewrite expr0 big_geq.
by rewrite (big_int_recr i) 1:// /= -ih exprD_nneg 1,2:// expr1 /#.
qed.

(* --------------------------------------------------------------------------
   STEP 10: MEMBERSHIP PLUMBING.  Two families, and they serve DIFFERENT
   obligations -- writing only the first is the mistake to avoid.

   (a) LIFTING (t2_mem*_rcons).  The node body appends one entry; every member
       already recorded must survive.  Each is the ordering lemma of STEP 2/4
       again: a committed index is < size ts, so nth_rcons returns it unchanged.
       These close the node BODY.

   (b) FOLDING (t2_mem*_fold).  Each loop EXIT must absorb the level it just
       finished into its parent disjunct -- a completed nodescl becomes part of
       memD, a completed nodest part of memC, and so on up.  These are pure
       index logic; the a-loop's ARITHMETIC debt is the size conjunct, which is
       what sum_nr_nodesf is for, not the membership one.  These close the four
       ENTRY+EXIT obligations below.

   Both families were named by adversarial review after a first pass that had
   the nth-characterisations and the freshness argument and silently omitted
   membership altogether.

   INTRO-PATTERN NOTE, measured not assumed (2026-08-06): EasyCrypt's `/\`
   destructuring is STRICTLY BINARY.  `move=> [h1 h2 h3]` on `A /\ B /\ C` is
   `nothing to introduce` at h3 -- NOT a partial intro.  Verified with a
   three-line standalone file.  So every pattern below takes the conjunction as
   ONE name and projects with smt.  The flat form is the natural thing to write
   and it fails at the THIRD name, which reads like a statement error rather
   than a syntax one. *)

(* --- (a) LIFTING --------------------------------------------------------- *)
lemma t2_memA_rcons (ts : (adrs * dgst) list) (si ji ui vi wi : int)
                    (y adx : adrs * dgst) :
     size ts = t2_off si ji ui vi wi
  => 0 <= ji < l' => 0 <= ui < k => 0 <= vi < a => 0 <= wi
  => (t2_memA (rcons ts y) si adx <=> t2_memA ts si adx).
proof.
move=> hsz hji hui hvi ge0_wi.
have hn : forall (i j u v w : int),
     0 <= i < si => 0 <= j < l' => 0 <= u < k => 0 <= v < a
  => 0 <= w < nr_nodesf (v + 1)
  => nth witness (rcons ts y) (t2_off i j u v w)
     = nth witness ts (t2_off i j u v w).
+ move=> i j u v w hi hj hu hv hw; rewrite nth_rcons hsz.
  by rewrite (: t2_off i j u v w < t2_off si ji ui vi wi)
             1:(t2_off_mono_i i j u v w si ji ui vi wi hi hj hu hv hw hji hui hvi ge0_wi).
rewrite /t2_memA; split.
+ move=> -[i j u v w] hbody; exists i j u v w.
  have hnn := hn i j u v w _ _ _ _ _; 1..5: smt().
  by rewrite -hnn.
move=> -[i j u v w] hbody; exists i j u v w.
have hnn := hn i j u v w _ _ _ _ _; 1..5: smt().
by rewrite hnn.
qed.

lemma t2_memB_rcons (ts : (adrs * dgst) list) (si ji ui vi wi : int)
                    (y adx : adrs * dgst) :
     size ts = t2_off si ji ui vi wi
  => 0 <= ui < k => 0 <= vi < a => 0 <= wi
  => (t2_memB (rcons ts y) si ji adx <=> t2_memB ts si ji adx).
proof.
move=> hsz hui hvi ge0_wi.
have hn : forall (j u v w : int),
     0 <= j < ji => 0 <= u < k => 0 <= v < a => 0 <= w < nr_nodesf (v + 1)
  => nth witness (rcons ts y) (t2_off si j u v w)
     = nth witness ts (t2_off si j u v w).
+ move=> j u v w hj hu hv hw; rewrite nth_rcons hsz.
  by rewrite (: t2_off si j u v w < t2_off si ji ui vi wi)
             1:(t2_off_mono_j si j u v w ji ui vi wi hj hu hv hw hui hvi ge0_wi).
rewrite /t2_memB; split.
+ move=> -[j u v w] hbody; exists j u v w.
  have hnn := hn j u v w _ _ _ _; 1..4: smt().
  by rewrite -hnn.
move=> -[j u v w] hbody; exists j u v w.
have hnn := hn j u v w _ _ _ _; 1..4: smt().
by rewrite hnn.
qed.

lemma t2_memC_rcons (ts : (adrs * dgst) list) (si ji ui vi wi : int)
                    (y adx : adrs * dgst) :
     size ts = t2_off si ji ui vi wi
  => 0 <= vi < a => 0 <= wi
  => (t2_memC (rcons ts y) si ji ui adx <=> t2_memC ts si ji ui adx).
proof.
move=> hsz hvi ge0_wi.
have hn : forall (u v w : int),
     0 <= u < ui => 0 <= v < a => 0 <= w < nr_nodesf (v + 1)
  => nth witness (rcons ts y) (t2_off si ji u v w)
     = nth witness ts (t2_off si ji u v w).
+ move=> u v w hu hv hw; rewrite nth_rcons hsz.
  by rewrite (: t2_off si ji u v w < t2_off si ji ui vi wi)
             1:(t2_off_mono_u si ji u v w ui vi wi hu hv hw hvi ge0_wi).
rewrite /t2_memC; split.
+ move=> -[u v w] hbody; exists u v w.
  have hnn := hn u v w _ _ _; 1..3: smt().
  by rewrite -hnn.
move=> -[u v w] hbody; exists u v w.
have hnn := hn u v w _ _ _; 1..3: smt().
by rewrite hnn.
qed.

lemma t2_memD_rcons (ts : (adrs * dgst) list) (si ji ui vi wi : int)
                    (y adx : adrs * dgst) :
     size ts = t2_off si ji ui vi wi
  => 0 <= wi
  => (t2_memD (rcons ts y) si ji ui vi adx <=> t2_memD ts si ji ui vi adx).
proof.
move=> hsz ge0_wi.
have hn : forall (v w : int),
     0 <= v < vi => 0 <= w < nr_nodesf (v + 1)
  => nth witness (rcons ts y) (t2_off si ji ui v w)
     = nth witness ts (t2_off si ji ui v w).
+ move=> v w hv hw; rewrite nth_rcons hsz.
  by rewrite (: t2_off si ji ui v w < t2_off si ji ui vi wi)
             1:(t2_off_mono_v si ji ui v w vi wi hv hw ge0_wi).
rewrite /t2_memD; split.
+ move=> -[v w] hbody; exists v w.
  have hnn := hn v w _ _; 1,2: smt().
  by rewrite -hnn.
move=> -[v w] hbody; exists v w.
have hnn := hn v w _ _; 1,2: smt().
by rewrite hnn.
qed.

(* The one that also GAINS a member: the appended entry is exactly the new
   memE witness, and it sits at index size ts. *)
lemma t2_memE_rcons (ts : (adrs * dgst) list) (si ji ui vi wi : int)
                    (y adx : adrs * dgst) :
     size ts = t2_off si ji ui vi wi
  => 0 <= wi
  => (t2_memE (rcons ts y) si ji ui vi (wi + 1) adx
      <=> (t2_memE ts si ji ui vi wi adx \/ adx = y)).
proof.
move=> hsz ge0_wi.
have hy : nth witness (rcons ts y) (t2_off si ji ui vi wi) = y.
+ by rewrite nth_rcons /#.
have hn : forall (w : int), 0 <= w < wi =>
     nth witness (rcons ts y) (t2_off si ji ui vi w)
   = nth witness ts (t2_off si ji ui vi w).
+ move=> w hw; rewrite nth_rcons hsz.
  by rewrite (: t2_off si ji ui vi w < t2_off si ji ui vi wi) 1:t2_off_mono_w 1:/#.
rewrite /t2_memE; split.
+ move=> -[w] hbody; case (w < wi) => [ltw | gew].
  - left; exists w.
    have hnn := hn w _; 1: smt().
    by rewrite -hnn; smt().
  right; have hw : w = wi by smt().
  by move: hbody; rewrite hw hy /#.
move=> -[hm | heqy].
+ move: hm => -[w] hbody; exists w.
  have hnn := hn w _; 1: smt().
  by rewrite hnn; smt().
by exists wi; rewrite hy heqy /#.
qed.

(* --- (b) FOLDING --------------------------------------------------------- *)
lemma t2_memD_fold (ts : (adrs * dgst) list) (si ji ui vi : int)
                   (adx : adrs * dgst) :
     0 <= vi
  => (t2_memD ts si ji ui (vi + 1) adx
      <=> (t2_memD ts si ji ui vi adx
           \/ t2_memE ts si ji ui vi (nr_nodesf (vi + 1)) adx)).
proof.
move=> ge0_vi; rewrite /t2_memD /t2_memE; split.
+ move=> -[v w] hbody; case (v < vi) => [ltvi | gevi].
  - by left; exists v w; smt().
  by right; exists w; smt().
move=> -[hm | hm].
+ by move: hm => -[v w] hbody; exists v w; smt().
by move: hm => -[w] hbody; exists vi w; smt().
qed.

lemma t2_memC_fold (ts : (adrs * dgst) list) (si ji ui : int)
                   (adx : adrs * dgst) :
     0 <= ui
  => (t2_memC ts si ji (ui + 1) adx
      <=> (t2_memC ts si ji ui adx \/ t2_memD ts si ji ui a adx)).
proof.
move=> ge0_ui; rewrite /t2_memC /t2_memD; split.
+ move=> -[u v w] hbody; case (u < ui) => [ltui | geui].
  - by left; exists u v w; smt().
  by right; exists v w; smt().
move=> -[hm | hm].
+ by move: hm => -[u v w] hbody; exists u v w; smt().
by move: hm => -[v w] hbody; exists ui v w; smt().
qed.

lemma t2_memB_fold (ts : (adrs * dgst) list) (si ji : int)
                   (adx : adrs * dgst) :
     0 <= ji
  => (t2_memB ts si (ji + 1) adx
      <=> (t2_memB ts si ji adx \/ t2_memC ts si ji k adx)).
proof.
move=> ge0_ji; rewrite /t2_memB /t2_memC; split.
+ move=> -[j u v w] hbody; case (j < ji) => [ltji | geji].
  - by left; exists j u v w; smt().
  by right; exists u v w; smt().
move=> -[hm | hm].
+ by move: hm => -[j u v w] hbody; exists j u v w; smt().
by move: hm => -[u v w] hbody; exists ji u v w; smt().
qed.

lemma t2_memA_fold (ts : (adrs * dgst) list) (si : int) (adx : adrs * dgst) :
     0 <= si
  => (t2_memA ts (si + 1) adx
      <=> (t2_memA ts si adx \/ t2_memB ts si l' adx)).
proof.
move=> ge0_si; rewrite /t2_memA /t2_memB; split.
+ move=> -[i j u v w] hbody; case (i < si) => [ltsi | gesi].
  - by left; exists i j u v w; smt().
  by right; exists j u v w; smt().
move=> -[hm | hm].
+ by move: hm => -[i j u v w] hbody; exists i j u v w; smt().
by move: hm => -[j u v w] hbody; exists si j u v w; smt().
qed.

(* --------------------------------------------------------------------------
   STEP 11: the packed breadth index is a valid FORS breadth index.

   Split out because it is the one validity side-condition that is NOT
   immediate: u * nr_nodesf (v+1) + w < k * nr_nodesf (v+1) is a multiplication
   fact, and smt does not find it unaided from 0 <= u < k and
   0 <= w < nr_nodesf (v+1). *)
lemma valid_tbf_pack (u w v : int) :
     0 <= u < k
  => 0 <= w < nr_nodesf (v + 1)
  => valid_tbfidx (v + 1) (u * nr_nodesf (v + 1) + w).
proof.
move=> [ge0_u ltk_u] [ge0_w ltnn_w]; rewrite /valid_tbfidx.
have gt0_nn : 0 < nr_nodesf (v + 1) by rewrite /nr_nodesf expr_gt0.
have hstep : (u + 1) * nr_nodesf (v + 1) <= k * nr_nodesf (v + 1).
+ by rewrite ler_pmul2r 1:// /#.
smt().
qed.

(* --------------------------------------------------------------------------
   STEP 12: the node address about to be appended occurs NOWHERE in ts.

   This is the uniq half of t2_good, packaged so the node body cites it once.
   Stated with the address FULLY UNFOLDED, deliberately: that is the form the
   equiv goal presents (the ts entry is built by the PROGRAM, not by our ops),
   so the citation site needs no rewriting, and the t2_adT folding happens here
   -- locally, where it is cheap.  The mixed fold/unfold normal form is the
   specific trap in this file: instantiating at the folded address matches a
   lemma's RHS and fails on its LHS, and the resulting error names the right
   lemma while pointing at the wrong thing.

   The hypotheses are the invariant's own conjuncts, in the order the invariant
   lists them, so the call site can pass them positionally. *)
lemma nodeaddr_notin_ts (ts : (adrs * dgst) list) (psi : pseed)
                        (sks : FTWES.skFORS list list) (skl : FTWES.skFORS list)
                        (skF : FTWES.skFORS) (lvs : dgstblock list)
                        (si ji ui vi wi : int) :
     size ts = t2_off si ji ui vi wi
  => 0 <= si < nr_trees 0 => 0 <= ji < l' => 0 <= ui < k => 0 <= vi < a
  => 0 <= wi < nr_nodesf (vi + 1)
  => (forall (adx : adrs * dgst), adx \in ts <=>
           (t2_memA ts si adx \/ t2_memB ts si ji adx \/ t2_memC ts si ji ui adx
            \/ t2_memD ts si ji ui vi adx \/ t2_memE ts si ji ui vi wi adx))
  => t2_nthA ts adz psi sks si
  => t2_nthB ts adz psi skl si ji
  => t2_nthC ts adz psi skF si ji ui
  => t2_nthD ts adz psi lvs si ji ui vi
  => t2_nthE ts adz psi lvs si ji ui vi wi
  => ! (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji)
          (vi + 1) (ui * nr_nodesf (vi + 1) + wi)
        \in unzip1 ts).
proof.
move=> hsz hsi hji hui hvi hwi hdef hA hB hC hD hE.
have hfresh : forall (i j u v w : int),
     0 <= i < nr_trees 0 => 0 <= j < l' => 0 <= u < k => 0 <= v < a
  => 0 <= w < nr_nodesf (v + 1)
  => (i <> si \/ j <> ji \/ u <> ui \/ v <> vi \/ w <> wi)
  => set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji)
       (vi + 1) (ui * nr_nodesf (vi + 1) + wi)
     <> set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
       (v + 1) (u * nr_nodesf (v + 1) + w).
+ move=> i j u v w hi hj hu hv hw hne.
  have := nodeaddr_fresh si ji ui vi wi i j u v w _ _ _ _ _ _ _ _ _ _ _.
  - by rewrite /valid_tidx.
  - by rewrite /valid_kpidx.
  - by rewrite /valid_thfidx /#.
  - by apply (valid_tbf_pack ui wi vi hui hwi).
  - by rewrite /valid_tidx.
  - by rewrite /valid_kpidx.
  - by rewrite /valid_thfidx /#.
  - by apply (valid_tbf_pack u w v hu hw).
  - exact hwi.
  - exact hw.
  - smt().
  by rewrite /t2_adT.
apply/negP => /mapP [adx] [hin hadx].
move: (hdef adx) => -[hfwd _]; move: (hfwd hin) => -[hm|[hm|[hm|[hm|hm]]]].
+ move: hm => -[i j u v w] hbody.
  have hi : 0 <= i < si by smt().
  have hj : 0 <= j < l' by smt().
  have hu : 0 <= u < k by smt().
  have hv : 0 <= v < a by smt().
  have hw : 0 <= w < nr_nodesf (v + 1) by smt().
  have hqn : adx = nth witness ts (t2_off i j u v w) by smt().
  have heq : adx = t2_entry_sk adz psi (nth witness (nth witness sks i) j)
                     i j u v w by rewrite hqn (hA i j u v w hi hj hu hv hw).
  have hf := hfresh i j u v w _ hj hu hv hw _; 1,2: smt().
  by move: hf; move: hadx;
     rewrite heq /t2_entry_sk /t2_entry_lvs /t2_adT /=; smt().
+ move: hm => -[j u v w] hbody.
  have hj : 0 <= j < ji by smt().
  have hu : 0 <= u < k by smt().
  have hv : 0 <= v < a by smt().
  have hw : 0 <= w < nr_nodesf (v + 1) by smt().
  have hqn : adx = nth witness ts (t2_off si j u v w) by smt().
  have heq : adx = t2_entry_sk adz psi (nth witness skl j) si j u v w
    by rewrite hqn (hB j u v w hj hu hv hw).
  have hf := hfresh si j u v w _ _ hu hv hw _; 1..3: smt().
  by move: hf; move: hadx;
     rewrite heq /t2_entry_sk /t2_entry_lvs /t2_adT /=; smt().
+ move: hm => -[u v w] hbody.
  have hu : 0 <= u < ui by smt().
  have hv : 0 <= v < a by smt().
  have hw : 0 <= w < nr_nodesf (v + 1) by smt().
  have hqn : adx = nth witness ts (t2_off si ji u v w) by smt().
  have heq : adx = t2_entry_sk adz psi skF si ji u v w
    by rewrite hqn (hC u v w hu hv hw).
  have hf := hfresh si ji u v w _ _ _ hv hw _; 1..4: smt().
  by move: hf; move: hadx;
     rewrite heq /t2_entry_sk /t2_entry_lvs /t2_adT /=; smt().
+ move: hm => -[v w] hbody.
  have hv : 0 <= v < vi by smt().
  have hw : 0 <= w < nr_nodesf (v + 1) by smt().
  have hqn : adx = nth witness ts (t2_off si ji ui v w) by smt().
  have heq : adx = t2_entry_lvs adz psi lvs si ji ui v w
    by rewrite hqn (hD v w hv hw).
  have hf := hfresh si ji ui v w _ _ _ _ hw _; 1..5: smt().
  by move: hf; move: hadx;
     rewrite heq /t2_entry_lvs /t2_adT /=; smt().
move: hm => -[w] hbody.
have hw : 0 <= w < wi by smt().
have hqn : adx = nth witness ts (t2_off si ji ui vi w) by smt().
have heq : adx = t2_entry_lvs adz psi lvs si ji ui vi w
  by rewrite hqn (hE w hw).
have hf := hfresh si ji ui vi w _ _ _ _ _ _; 1..6: smt().
by move: hf; move: hadx;
   rewrite heq /t2_entry_lvs /t2_adT /=; smt().
qed.
(* --------------------------------------------------------------------------
   STEP 14: the LEVEL-FOLD family -- what a completed nodescl contributes to
   its parent nodest.

   THREE obligations, not one, and the mem half alone is the trap.  Reading the
   node-loop EXIT goal (dumped 2026-08-06) the post asks for all of:

     t2_memD  ts si ji ui (size (rcons nodest nodescl))   <- t2_memD_fold  (STEP 10)
     t2_nthD  ts ad0 psi lvs si ji ui (size (rcons ...))  <- t2_nthD_fold  (here)
     t2_ndst  psi adT lvs ui (rcons nodest nodescl)       <- t2_ndst_fold  (here)
     size ts  = ... + bigi 1 (size (rcons ...) + 1)       <- bigi_nnf_recr (here)

   i.e. every family the invariant carries has to be folded, not just the
   membership one.  Writing t2_mem*_fold and stopping is the same shape of miss
   as writing the t2_nth*_append family and omitting t2_mem* was in STEP 10 --
   the goal simply does not mention the piece you left out until you get there.

   NOTE the size_rcons normalisation AGAIN: the post says
   `size (rcons nodest nodescl)`, never `size nodest + 1`.  Each lemma below is
   stated at `+ 1` and the call site must normalise first. *)

lemma t2_nthD_fold (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                   (lvs : dgstblock list) (si ji ui vi : int) :
     0 <= vi
  => t2_nthD ts ad0 psi lvs si ji ui vi
  => t2_nthE ts ad0 psi lvs si ji ui vi (nr_nodesf (vi + 1))
  => t2_nthD ts ad0 psi lvs si ji ui (vi + 1).
proof.
move=> ge0_vi hD hE v w hv hw.
case (v < vi) => [ltvi | gevi]; 1: by apply hD; smt().
have eqv : v = vi by smt().
by rewrite eqv; apply hE; smt().
qed.

lemma t2_ndst_fold (psi : pseed) (adT : adrs) (lvs : dgstblock list)
                   (ui : int) (ndst : dgstblock list list)
                   (ndscl : dgstblock list) :
     t2_ndst psi adT lvs ui ndst
  => t2_ndscl psi adT lvs ui (size ndst) ndscl
  => size ndscl = nr_nodesf (size ndst + 1)
  => t2_ndst psi adT lvs ui (rcons ndst ndscl).
proof.
move=> hndst hndscl hszcl v w hv hw.
move: hv; rewrite size_rcons => hv.
rewrite nth_rcons.
case (v < size ndst) => [ltv | gev]; 1: by apply hndst; smt().
have -> /= : v = size ndst by smt().
by apply hndscl; smt().
qed.

(* The size fold.  big_int_recr needs its index SPELLED OUT -- inferring it has
   failed here three times -- and the sum is stated at `v + 1 + 1` rather than
   `v + 2` because that is the shape `size_rcons` leaves behind and the two are
   not syntactically equal. *)
lemma bigi_nnf_recr (v : int) :
     0 <= v
  => bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1 + 1)
     = bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + nr_nodesf (v + 1).
proof. by move=> ge0_v; rewrite (big_int_recr (v + 1)) 1:/#. qed.

(* Entry-side vacuity: at nodescl = [] the memE / nthE / ndscl layers say
   nothing, which is exactly what lets the 5-disjunct node invariant collapse
   back to the 4-disjunct one the a-loop carries. *)
lemma t2_memE_nil (ts : (adrs * dgst) list) (si ji ui vi : int)
                  (adx : adrs * dgst) :
  ! t2_memE ts si ji ui vi 0 adx.
proof. by rewrite /t2_memE; apply/negP => -[w] hbody; smt(). qed.

lemma t2_nthE_nil (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                  (lvs : dgstblock list) (si ji ui vi : int) :
  t2_nthE ts ad0 psi lvs si ji ui vi 0.
proof. by rewrite /t2_nthE => w hw; smt(). qed.

lemma t2_ndscl_nil (psi : pseed) (adT : adrs) (lvs : dgstblock list)
                   (ui vi : int) :
  t2_ndscl psi adT lvs ui vi [].
proof. by rewrite /t2_ndscl /= => w hw; smt(). qed.
(* D-level vacuity, for the a-loop ENTRY (nodest = []).  Same three shapes as
   the E-level trio at STEP 14, one layer up: at nodest = [] the memD / nthD /
   ndst layers say nothing, which is what lets the 4-disjunct a-loop invariant
   collapse back onto the 3-disjunct k-loop one. *)
lemma t2_memD_nil (ts : (adrs * dgst) list) (si ji ui : int)
                  (adx : adrs * dgst) :
  ! t2_memD ts si ji ui 0 adx.
proof. by rewrite /t2_memD; apply/negP => -[v w] hbody; smt(). qed.

lemma t2_nthD_nil (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                  (lvs : dgstblock list) (si ji ui : int) :
  t2_nthD ts ad0 psi lvs si ji ui 0.
proof. by rewrite /t2_nthD => v w hv hw; smt(). qed.

lemma t2_ndst_nil (psi : pseed) (adT : adrs) (lvs : dgstblock list) (ui : int) :
  t2_ndst psi adT lvs ui [].
proof. by rewrite /t2_ndst /= => v w hv hw; smt(). qed.

lemma bigi_nnf_nil :
  bigi predT (fun (m : int) => nr_nodesf m) 1 (0 + 1) = 0.
proof. by rewrite big_geq. qed.

(* --------------------------------------------------------------------------
   STEP 16: the TREE-fold -- what a completed FORS tree contributes to its
   keypair.  This is the a-loop exit's counterpart to STEP 14's level fold, and
   it is the ONE fold that is not pure index bookkeeping.

   t2_nthD speaks of `lvs` (the leaf list the loop actually built); t2_nthC
   speaks of `skF` and reconstructs its leaves as
   `fors_leaves_op_cube skF psi (t2_adT ad0 si ji) ui`.  So folding D into C
   consumes exactly the leaf loop's postcondition, supplied here as an explicit
   premise so the citation site can just hand over the `hlfR` it derives from
   cube_is_mkseq.  Taking `lvs` as an arbitrary list with `size lvs = t` would
   NOT do -- that was the open question about whether fors_leaves_op_cube admits
   a prefix characterisation, and the answer is that it does not have to: the
   leaf loop carries a mkseq and cube_is_mkseq converts it in one step. *)
lemma t2_nthC_fold (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                   (skF : FTWES.skFORS) (lvs : dgstblock list)
                   (si ji ui : int) :
     0 <= ui
  => lvs = fors_leaves_op_cube skF psi (t2_adT ad0 si ji) ui
  => t2_nthC ts ad0 psi skF si ji ui
  => t2_nthD ts ad0 psi lvs si ji ui a
  => t2_nthC ts ad0 psi skF si ji (ui + 1).
proof.
move=> ge0_ui hlvs hC hD u v w hu hv hw.
case (u < ui) => [ltui | geui]; 1: by apply hC; smt().
have equ : u = ui by smt().
rewrite equ /t2_entry_sk -hlvs.
by apply hD; smt().
qed.

(* The a-exit's SIZE fold, and the use sum_nr_nodesf was retracted-and-reproved
   for: a full tree's layer sum is exactly one t2_span, so the per-layer bigi
   term collapses into the per-tree term.  ltnn1_bignna cannot do this -- it is
   a strict PREFIX bound, and a bound cannot prove an equality. *)
lemma t2_size_fold_a (x u : int) :
    x + u * t2_span + bigi predT (fun (m : int) => nr_nodesf m) 1 (a + 1)
  = x + (u + 1) * t2_span.
proof. by rewrite sum_nr_nodesf; ring. qed.

(* --------------------------------------------------------------------------
   STEP 17: the KEYPAIR and INSTANCE folds, for the k- and l'-loop exits.

   These MUST be stated over the RCONS'D list.  The program does
   `skFORSl <- rcons skFORSl skFORS` (resp. `skFORSs <- rcons skFORSs skFORSl`)
   and the fold happens after the append, so a lemma phrased over `skl` alone
   proves something true and does not apply at the call site.  The `size skl =
   ji` premise is what lets nth_rcons split the j < ji / j = ji cases. *)
lemma t2_nthB_fold (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                   (skl : FTWES.skFORS list) (skF : FTWES.skFORS)
                   (si ji : int) :
     size skl = ji
  => t2_nthB ts ad0 psi skl si ji
  => t2_nthC ts ad0 psi skF si ji k
  => t2_nthB ts ad0 psi (rcons skl skF) si (ji + 1).
proof.
move=> hsz hB hC j u v w hj hu hv hw.
rewrite nth_rcons hsz.
case (j < ji) => [ltji | geji]; 1: by apply hB; smt().
have eqj : j = ji by smt().
by rewrite eqj /=; apply hC; smt().
qed.

lemma t2_nthA_fold (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                   (sks : FTWES.skFORS list list) (skl : FTWES.skFORS list)
                   (si : int) :
     size sks = si
  => t2_nthA ts ad0 psi sks si
  => t2_nthB ts ad0 psi skl si l'
  => t2_nthA ts ad0 psi (rcons sks skl) (si + 1).
proof.
move=> hsz hA hB i j u v w hi hj hu hv hw.
rewrite nth_rcons hsz.
case (i < si) => [ltsi | gesi]; 1: by apply hA; smt().
have eqi : i = si by smt().
by rewrite eqi /=; apply hB; smt().
qed.

(* The corresponding size folds.  Pure ring, unlike t2_size_fold_a which had to
   collapse a layer sum. *)
lemma t2_size_fold_k (x j : int) :
  x + j * k * t2_span + k * t2_span = x + (j + 1) * k * t2_span.
proof. by ring. qed.

lemma t2_size_fold_l (x i : int) :
  x + i * l' * k * t2_span + l' * k * t2_span = x + (i + 1) * l' * k * t2_span.
proof. by ring. qed.

(* C-level vacuity, for the k-loop ENTRY (rootsk = []).  Third instance of the
   same trio, one layer up again from STEP 14's E-level and the D-level pair. *)
lemma t2_memC_nil (ts : (adrs * dgst) list) (si ji : int) (adx : adrs * dgst) :
  ! t2_memC ts si ji 0 adx.
proof. by rewrite /t2_memC; apply/negP => -[u v w] hbody; smt(). qed.

lemma t2_nthC_nil (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                  (skF : FTWES.skFORS) (si ji : int) :
  t2_nthC ts ad0 psi skF si ji 0.
proof. by rewrite /t2_nthC => u v w hu hv hw; smt(). qed.

(* The trco challenge's INPUT SIZE.  `trco = thfc (8 * n * k)` by definition, so
   the inlined right-hand side's `thfc (size (flatten (map val rs))) ..` only
   matches once that size is computed.  The computation is MM45's own
   (FORS_ES.ec:5748-5750), isolated here so the k- and l'-loop exits cite it
   instead of carrying three lines of big-operator manipulation inline. *)
lemma size_flatten_roots (rs : dgstblock list) :
  size rs = k => size (flatten (map DigestBlock.val rs)) = 8 * n * k.
proof.
move=> hsz.
rewrite size_flatten sumzE 2!big_map /(\o) /predT /= -/predT.
rewrite (eq_bigr _ _ (fun _ => 8 * n)) => [x _ /= |]; 1: by rewrite DigestBlock.valP.
by rewrite big_constz count_predT hsz.
qed.

(* The TRCO address is well-typed.  This is the one `tws` obligation that is not
   t2_good riding through: the OC.query following the k-loop appends the trco
   compression's address, and the tws predicate's LEFT disjunct
   (get_typeidx = trcotype) is what admits it.

   Discharged through adzf for the reason recorded at the adzf block: our adz is
   SPHINCS_PLUS's CHAIN zero address and does NOT satisfy valid_fadrs, but every
   address here enters as `set_typeidx adz trhftype`, which settype_adz_eq
   rewrites to the concrete valid FORS address.

   THREE premises, not five.  Six attempts assumed five -- MM45's lemma has five
   hypotheses, but `//` discharges `valid_tidx si` and `valid_kpidx ji` from the
   context straight away, so the tactics that follow address only what is left.
   Assuming the arity instead of dumping it cost every one of those attempts;
   the dump also showed that the surviving `valid_tidx` premise is the
   TWO-argument SPHINCS_PLUS one, so the unqualified name was correct and
   `FTWES.valid_tidx` (which I tried) does not even exist. *)
lemma trcoaddr_gettype (si ji : int) :
     0 <= si < nr_trees 0 => 0 <= ji < l'
  => get_typeidx (set_kpidx (set_typeidx
        (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji) trcotype)
        (FTWES.get_kpidx
           (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji)))
     = trcotype.
proof.
move=> hsi hji.
rewrite !settype_adz_eq.
rewrite FTWES.gettype_setkp2type2trhtrco //.
+ by rewrite adzf_val.
+ by rewrite adzf_val /= /valid_tidx /nr_trees; smt(expr_gt0).
by rewrite FTWES.vkpidx_setkpttype 1:valid_fadrs_adzf //; smt().
qed.

(* The l'-exit's size fold.  Stated with (2 ^ a - 1) spelled out, and with no
   leading `x` term, because the OUTER invariant's size conjunct is exactly
   `size ts = size skFORSs * l' * k * (2 ^ a - 1)` -- no prefix to match against,
   and t2_span not yet folded at that level. *)
lemma t2_size_fold_l0 (i : int) :
    i * l' * k * (2 ^ a - 1) + l' * k * (2 ^ a - 1)
  = (i + 1) * l' * k * (2 ^ a - 1).
proof. by ring. qed.

(* The SM_DT_TCR target bound.  SM_DT_TCR_C's t_smdttcr is l * k * (t - 1); this
   file's size conjunct gives size ts = nr_trees 0 * l' * k * (2 ^ a - 1), and
   these agree exactly once nr_trees 0 * l' is folded to l.  MM45 cite `dval`
   for this step; we have no such lemma, so T3 proved it and this is the same
   proof. *)
lemma nrtrees_lp_l : nr_trees 0 * l' = l.
proof.
rewrite /nr_trees /l' /l /h -exprD_nneg.
+ smt(ge1_hp ge1_d).
+ smt(ge1_hp).
by congr; ring.
qed.

(* RETRACTION, and it matters for how the collision core is scoped.  I claimed
   twice that C10 replaces MM45's index extractor with M.F.hC and that "the
   chunking around them does not [transfer], and that delta is the actual work".
   THAT IS WRONG.  FORS_C10.ec:211 defines

       op hC (mk : mkey) (m : msg) = g (mco mk m)

   and GprocFORSC10.ec's clone binds F.g <- FTWES.g and F.mco <- FTWES.mco.  So
   M.F.hC IS MM45's `g (mco mk m)`, by pure delta -- the lemma below is proved
   by `rewrite /M.F.hC` alone.  The collision core is therefore a PORT of
   FORS_ES.ec:5861-5943, not a re-derivation, and the estimate I gave was too
   pessimistic. *)
lemma hC_is_g (mk : mkey) (m : msg) :
  M.F.hC mk m = FTWES.g (FTWES.mco mk m).
proof. by rewrite /M.F.hC. qed.

(* THE hC COMPONENT BRIDGES, lifted from T3 (_t3.ec:346-367).  The inlined
   pkFORS' loop indexes by the concrete take/drop chunk; MM45's collision
   argument reads the three components of `g (mco mk m)`.  All three unfold
   definitionally -- see hC_is_g -- and stating them up front is T3's lesson:
   discovering mid-goal which component a step needs costs a probe each. *)
lemma hC_chunk (mk : mkey) (m : msg) (i : int) :
  0 <= i < k =>
  (nth witness (M.F.hC mk m) i).`3
  = bs2int (rev (take a (drop (a * i) (FTWES.BLKAL.val (FTWES.mco mk m).`1)))).
proof.
move=> rng_i.
rewrite /M.F.hC /FTWES.g /= nth_mkseq 1:// /= /chunk nth_mkseq //.
by rewrite FTWES.BLKAL.valP mulzK; smt(ge1_a).
qed.

lemma hC_pos (mk : mkey) (m : msg) (i : int) :
  0 <= i < k => (nth witness (M.F.hC mk m) i).`2 = i.
proof. by move=> rng_i; rewrite /M.F.hC /FTWES.g /= nth_mkseq. qed.

lemma hC_inst (mk : mkey) (m : msg) (i : int) :
  0 <= i < k =>
  (nth witness (M.F.hC mk m) i).`1 = Index.val (FTWES.mco mk m).`2.
proof. by move=> rng_i; rewrite /M.F.hC /FTWES.g /= nth_mkseq. qed.

(* --------------------------------------------------------------------------
   STEP 18: RAW <-> OP bridges.

   The outer and l'-loop invariants predate the op layer and are written out
   longhand; the k-, a- and node-loop invariants use t2_mem*/t2_nth*.  So the
   k-loop entry+exit has to cross that seam.  The two forms are DEFINITIONALLY
   equal -- the longhand text is exactly the ops unfolded -- so each bridge is
   pure delta, and stating them as lemmas (rather than unfolding nine ops inline
   at the call site) keeps the seam visible and testable.

   Deliberately NOT fixed by rewriting the two older invariants: they are
   arguments of `while`s whose surrounding obligations are already discharged,
   and a semantically-identical edit there would still force those proofs to be
   re-checked for no gain.  The seam is one-directional and cheap. *)
lemma t2_memA_raw (ts : (adrs * dgst) list) (si : int) (adx : adrs * dgst) :
  t2_memA ts si adx
  <=> (exists (i j u v w : int),
         0 <= i < si /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < a /\
         0 <= w < nr_nodesf (v + 1) /\
         adx = nth witness ts
                 (i * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1)
                  + u * (2 ^ a - 1)
                  + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)).
proof. by rewrite /t2_memA /t2_off /t2_span. qed.

lemma t2_memB_raw (ts : (adrs * dgst) list) (si ji : int) (adx : adrs * dgst) :
  t2_memB ts si ji adx
  <=> (exists (j u v w : int),
         0 <= j < ji /\ 0 <= u < k /\ 0 <= v < a /\
         0 <= w < nr_nodesf (v + 1) /\
         adx = nth witness ts
                 (si * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1)
                  + u * (2 ^ a - 1)
                  + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)).
proof. by rewrite /t2_memB /t2_off /t2_span. qed.

lemma t2_nthA_raw (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                  (sks : FTWES.skFORS list list) (si : int) :
  t2_nthA ts ad0 psi sks si
  <=> (forall (i j u v w : int),
         0 <= i < si => 0 <= j < l' => 0 <= u < k =>
         0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
         nth witness ts
             (i * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
              + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
         = (set_thtbidx (set_kpidx (set_tidx (set_typeidx ad0 trhftype) i) j)
                        (v + 1) (u * nr_nodesf (v + 1) + w),
            let lvs = fors_leaves_op_cube
                        (nth witness (nth witness sks i) j) psi
                        (set_kpidx (set_tidx (set_typeidx ad0 trhftype) i) j) u in
              DigestBlock.val (FTWES.val_bt_trh_gen psi
                (set_kpidx (set_tidx (set_typeidx ad0 trhftype) i) j)
                (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w))))) v
                (u * nr_nodesf v + 2 * w))
              ++
              DigestBlock.val (FTWES.val_bt_trh_gen psi
                (set_kpidx (set_tidx (set_typeidx ad0 trhftype) i) j)
                (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w + 1))))) v
                (u * nr_nodesf v + 2 * w + 1)))).
proof.
by rewrite /t2_nthA /t2_off /t2_span /t2_entry_sk /t2_entry_lvs /t2_pre /t2_adT.
qed.

lemma t2_nthB_raw (ts : (adrs * dgst) list) (ad0 : adrs) (psi : pseed)
                  (skl : FTWES.skFORS list) (si ji : int) :
  t2_nthB ts ad0 psi skl si ji
  <=> (forall (j u v w : int),
         0 <= j < ji => 0 <= u < k =>
         0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
         nth witness ts
             (si * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
              + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
         = (set_thtbidx (set_kpidx (set_tidx (set_typeidx ad0 trhftype) si) j)
                        (v + 1) (u * nr_nodesf (v + 1) + w),
            let lvs = fors_leaves_op_cube (nth witness skl j) psi
                        (set_kpidx (set_tidx (set_typeidx ad0 trhftype) si) j) u in
              DigestBlock.val (FTWES.val_bt_trh_gen psi
                (set_kpidx (set_tidx (set_typeidx ad0 trhftype) si) j)
                (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w))))) v
                (u * nr_nodesf v + 2 * w))
              ++
              DigestBlock.val (FTWES.val_bt_trh_gen psi
                (set_kpidx (set_tidx (set_typeidx ad0 trhftype) si) j)
                (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w + 1))))) v
                (u * nr_nodesf v + 2 * w + 1)))).
proof.
by rewrite /t2_nthB /t2_off /t2_span /t2_entry_sk /t2_entry_lvs /t2_pre /t2_adT.
qed.

(* --------------------------------------------------------------------------
   STEP 15: the LEAF address.  Layer 0, so its tree-height index is ZERO --
   which is why leaf queries could not live in `ts` (whose predicate demands
   get_thidx <> 0) and indeed do not: see the source check at t2_good.  In
   `tws` the predicate is the `trcotype \/ get_thidx = 0` disjunction, and this
   supplies the right disjunct.

   The valid_tbfidx side-condition is the awkward one -- nr_nodesf 0 = t, so it
   needs ui * t + vi < k * t from ui < k and vi < t, which smt does not find
   unaided.  The arithmetic is MM45's (FORS_ES.ec:6266), lifted from where T3
   already had to do it inline (_t3.ec:828-836). *)
lemma leafaddr_thidx0 (si ji ui vi : int) :
     0 <= si < nr_trees 0 => 0 <= ji < l' => 0 <= ui < k => 0 <= vi < t
  => FTWES.get_thidx (set_thtbidx
        (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji)
        0 (ui * t + vi)) = 0.
proof.
move=> hsi hji hui hvi.
apply (getth_leafaddr si ji (ui * t + vi)).
+ by rewrite /valid_tidx.
+ by rewrite /valid_kpidx.
+ by rewrite /valid_thfidx; smt(ge1_a).
rewrite /valid_tbfidx /nr_nodesf /=.
split => [| _]; 1: smt(expr_ge0).
by rewrite (: k = k - 1 + 1) 1:// mulrDl /= ler_lt_add 1:/t
           1:ler_pmul2r 3:// 1:expr_gt0 1:// /#.
qed.

(* =========================================================================== *)

(* --------------------------------------------------------------------------
   STEP 13: the four NODE-BODY STEPS, each stated exactly as the equiv goal
   presents it so the body is a list of citations rather than a proof.

   NORMAL FORM.  The equiv goal mixes the two forms of the tree address: the
   `ts` entry and the `trh` call carry it FULLY UNFOLDED (the program builds
   it), while the invariant's t2_ndst / t2_ndscl / t2_nth* carry it FOLDED as
   t2_adT.  Each lemma below is stated in whichever form its own position uses,
   and drives to the unfolded form internally.  Getting this backwards produces
   an error that names the right lemma while pointing at the wrong side of it.
   -------------------------------------------------------------------------- *)

(* Conjunct 1: the membership iff survives the append, gaining exactly one new
   memE witness. *)
lemma t2_otsdef_step (ts : (adrs * dgst) list) (si ji ui vi wi : int)
                     (y : adrs * dgst) :
     size ts = t2_off si ji ui vi wi
  => 0 <= ji < l' => 0 <= ui < k => 0 <= vi < a => 0 <= wi
  => (forall (adx : adrs * dgst), adx \in ts <=>
        (t2_memA ts si adx \/ t2_memB ts si ji adx \/ t2_memC ts si ji ui adx
         \/ t2_memD ts si ji ui vi adx \/ t2_memE ts si ji ui vi wi adx))
  => (forall (adx : adrs * dgst),
        (adx \in rcons ts y =>
           (t2_memA (rcons ts y) si adx \/ t2_memB (rcons ts y) si ji adx
            \/ t2_memC (rcons ts y) si ji ui adx
            \/ t2_memD (rcons ts y) si ji ui vi adx
            \/ t2_memE (rcons ts y) si ji ui vi (wi + 1) adx))
        /\ ((t2_memA (rcons ts y) si adx \/ t2_memB (rcons ts y) si ji adx
             \/ t2_memC (rcons ts y) si ji ui adx
             \/ t2_memD (rcons ts y) si ji ui vi adx
             \/ t2_memE (rcons ts y) si ji ui vi (wi + 1) adx)
            => adx \in rcons ts y)).
(* NOTE the SPLIT shape.  `=> />` has already turned the goal's `<=>` into a
   conjunction of two implications, so a lemma stated with `<=>` proves the
   right thing and still fails to apply.  Copy the statement out of the goal
   dump; do not re-derive it from the op definitions. *)
proof.
move=> hsz hji hui hvi ge0_wi hdef adx.
rewrite mem_rcons /=.
rewrite (t2_memA_rcons ts si ji ui vi wi y adx hsz hji hui hvi ge0_wi).
rewrite (t2_memB_rcons ts si ji ui vi wi y adx hsz hui hvi ge0_wi).
rewrite (t2_memC_rcons ts si ji ui vi wi y adx hsz hvi ge0_wi).
rewrite (t2_memD_rcons ts si ji ui vi wi y adx hsz ge0_wi).
rewrite (t2_memE_rcons ts si ji ui vi wi y adx hsz ge0_wi).
by move: (hdef adx) => -[h1 h2]; smt().
qed.

(* Conjunct 6: the CHALLENGE INPUT recorded at the new index is the sibling
   concatenation -- node_children_step -- and every earlier index is untouched
   -- t2_nthE_append. *)
lemma t2_nthE_step (ts : (adrs * dgst) list) (psi : pseed) (lvs : dgstblock list)
                   (ndst : dgstblock list list) (si ji ui vi wi : int) :
     size ts = t2_off si ji ui vi wi
  => size lvs = t
  => 0 <= vi < a
  => 0 <= wi < nr_nodesf (vi + 1)
  => size ndst = vi
  => t2_ndst psi (t2_adT adz si ji) lvs ui ndst
  => t2_nthE ts adz psi lvs si ji ui vi wi
  => t2_nthE (rcons ts
        (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji)
           (vi + 1) (ui * nr_nodesf (vi + 1) + wi),
         DigestBlock.val (nth witness (last lvs ndst) (2 * wi))
         ++ DigestBlock.val (nth witness (last lvs ndst) (2 * wi + 1))))
       adz psi lvs si ji ui vi (wi + 1).
proof.
move=> hsz eqt_szlvs hvi hwi hszn hndst hE.
have hchild :
     DigestBlock.val (nth witness (last lvs ndst) (2 * wi))
  ++ DigestBlock.val (nth witness (last lvs ndst) (2 * wi + 1))
   = t2_pre psi (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji)
       lvs ui vi wi.
+ rewrite /t2_pre -hszn.
  apply (node_children_step psi
           (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji)
           lvs ui ndst wi).
  - exact eqt_szlvs.
  - smt(size_ge0).
  - by move: hndst; rewrite /t2_ndst /t2_nodeval /t2_adT.
  smt().
rewrite hchild.
have -> :
  (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji)
     (vi + 1) (ui * nr_nodesf (vi + 1) + wi),
   t2_pre psi (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji) lvs ui vi wi)
  = t2_entry_lvs adz psi lvs si ji ui vi wi
  by rewrite /t2_entry_lvs /t2_adT.
by apply (t2_nthE_append ts adz psi lvs si ji ui vi wi hsz _ hE); smt().
qed.

(* Conjunct 7: the RETURNED node at the new index is the parent value --
   node_level_step, lifted unchanged from T3. *)
lemma t2_ndscl_step (psi : pseed) (lvs : dgstblock list)
                    (ndst : dgstblock list list) (ndscl : dgstblock list)
                    (si ji ui vi : int) :
     size lvs = t
  => 0 <= vi < a
  => size ndst = vi
  => size ndscl < nr_nodesf (vi + 1)
  => t2_ndst psi (t2_adT adz si ji) lvs ui ndst
  => t2_ndscl psi (t2_adT adz si ji) lvs ui vi ndscl
  => t2_ndscl psi (t2_adT adz si ji) lvs ui vi
       (rcons ndscl
          (trh psi
             (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji)
                (vi + 1) (ui * nr_nodesf (vi + 1) + size ndscl))
             (DigestBlock.val (nth witness (last lvs ndst) (2 * size ndscl))
              ++ DigestBlock.val (nth witness (last lvs ndst) (2 * size ndscl + 1))))).
proof.
move=> eqt_szlvs hvi hszn hltn hndst hndscl.
rewrite /t2_ndscl => w hw.
rewrite nth_rcons.
case (w < size ndscl) => [hlt | hge].
+ by move: hndscl; rewrite /t2_ndscl => h; apply h; smt().
have -> /= : w = size ndscl by smt(size_rcons).
rewrite /t2_nodeval /t2_adT -hszn.
apply (node_level_step psi
         (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji)
         lvs ui ndst (size ndscl)).
+ exact eqt_szlvs.
+ smt(size_ge0).
+ by move: hndst; rewrite /t2_ndst /t2_nodeval /t2_adT.
smt(size_ge0).
qed.

(* Conjunct 9: the new address is a well-formed FORS tree-hash address at a
   NON-ZERO layer.  The layer is vi + 1 and vi >= 0, which is why the node loop
   -- unlike the leaf loop -- never threatens the get_thidx <> 0 half. *)
lemma nodeaddr_good (si ji ui vi wi : int) :
     0 <= si < nr_trees 0 => 0 <= ji < l' => 0 <= ui < k => 0 <= vi < a
  => 0 <= wi < nr_nodesf (vi + 1)
  => get_typeidx (set_thtbidx
        (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji)
        (vi + 1) (ui * nr_nodesf (vi + 1) + wi)) = trhftype
     /\ FTWES.get_thidx (set_thtbidx
        (set_kpidx (set_tidx (set_typeidx adz trhftype) si) ji)
        (vi + 1) (ui * nr_nodesf (vi + 1) + wi)) <> 0.
proof.
move=> hsi hji hui hvi hwi.
have vt : valid_tidx 0 si by rewrite /valid_tidx.
have vk : valid_kpidx ji by rewrite /valid_kpidx.
have vh : valid_thfidx (vi + 1) by rewrite /valid_thfidx /#.
have vb : valid_tbfidx (vi + 1) (ui * nr_nodesf (vi + 1) + wi)
  by apply (valid_tbf_pack ui wi vi hui hwi).
split.
+ by apply (gettype_nodeaddr si ji (vi + 1) (ui * nr_nodesf (vi + 1) + wi)).
by rewrite (getth_nodeaddr si ji (vi + 1) (ui * nr_nodesf (vi + 1) + wi)) //; smt().
qed.
(* ===========================================================================
   THE T2 BOUND.  Stated over Gproc_VI for the same reason T3 is: MM45 prove
   their TRH branch over the restructured game (FORS_ES.ec:4828-4832), and the
   certified hop gproc_V_VI_eq carries it back to the _V form that
   gproc_Q_decomposition's second term actually is.
   =========================================================================== *)
lemma t2_trh_bound_VI
  (A <: Adv_EUFCMA_Gproc{-O_CMA_Gproc_I, -EUF_CMA_Gproc_I, -EUF_CMA_Gproc_V,
                         -R_TRH_Gproc,
                         -FTWES.TRHC_TCR.O_SMDTTCR_Default,
                         -FTWES.TRHC.O_THFC_Default}) &m :
    Pr[EUF_CMA_Gproc_VI(A).main() @ &m :
         ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
         /\ EUF_CMA_Gproc_V.valid_TRHTCR]
  <= Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(A),
           FTWES.TRHC_TCR.O_SMDTTCR_Default, FTWES.TRHC.O_THFC_Default).main() @ &m : res].
proof.
(* SPLIT POINT, by the same accounting that made T3 `seq 4 9`:
   left  4 = ad, ps, keygen (GprocKgVI.keygen is ONE statement), O_CMA init;
   right 9 = pp, OC.init, O.init, then the inlined pick's ad/skFORSs/pkFORSs/
             while, then `ps <- pp`, then the inlined find's O_CMA init.
   The `ps <- pp` at right 9 is the one T3 originally missed. *)
byequiv => //.
proc.
inline{2} 5; inline{2} 4.
seq 4 9 : (   ={glob A, glob O_CMA_Gproc_I}
           /\ ps{1} = pp{2}
           /\ ps{2} = pp{2}
           /\ ad{1} = adz
           /\ ad{1} = R_TRH_Gproc.ad{2}
           /\ skFORSnt{1} = R_TRH_Gproc.skFORSs{2}
           /\ pkFORSnt{1} = R_TRH_Gproc.pkFORSs{2}
           (* THE TS LAYOUT.  MM45's five-index address (FORS_ES.ec:4844-4859):
              instance i, keypair j, tree u, layer v, breadth w, flattened as
              i*l'*k*(t-1) + j*k*(t-1) + u*(t-1) + bigi nr_nodesf 1 (v+1) + w.
              The ENTRY's second component is the CONCATENATION of the two
              children -- this is the substantive difference from T3, where the
              target was a single root row. *)
           /\ (forall (i j u v w : int),
                 0 <= i < nr_trees 0 => 0 <= j < l' => 0 <= u < k =>
                 0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
                 nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     (i * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                      + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
                 = (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                                (v + 1) (u * nr_nodesf (v + 1) + w),
                    let lvs = fors_leaves_op_cube
                                (nth witness (nth witness R_TRH_Gproc.skFORSs{2} i) j) pp{2}
                                (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j) u in
                      DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                        (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                        (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w))))) v
                        (u * nr_nodesf v + 2 * w))
                      ++
                      DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                        (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                        (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w + 1))))) v
                        (u * nr_nodesf v + 2 * w + 1))))
           /\ uniq (unzip1 FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2})
           /\ all (fun (ad : adrs) => get_typeidx ad = trhftype /\ FTWES.get_thidx ad <> 0)
                  (unzip1 FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2})
           /\ all (fun (ad : adrs) => get_typeidx ad = trcotype \/ FTWES.get_thidx ad = 0)
                  FTWES.TRHC.O_THFC_Default.tws{2}
           /\ size FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
              = nr_trees 0 * l' * k * (2 ^ a - 1)).
+ (* T2-PREFIX.  Same opening as T3's: our keygen is a CALL, so it and
     GprocTreeVI.root must be inlined to expose the loops that align with
     R_TRH_Gproc.pick()'s query layers. *)
  inline{1} 3.
  inline{1} GprocTreeVI.root.
  inline{1} O_CMA_Gproc_I.init.
  inline{2} O_CMA_Gproc_I.init.
  wp => /=.
  while (   ps0{1} = pp{2}
         /\ ps0{1} = FTWES.TRHC_TCR.O_SMDTTCR_Default.pp{2}
         /\ ps0{1} = FTWES.TRHC.O_THFC_Default.pp{2}
         /\ ad0{1} = adz
         /\ ad0{1} = R_TRH_Gproc.ad{2}
         /\ skFORSnt0{1} = R_TRH_Gproc.skFORSs{2}
         /\ pkFORSnt0{1} = R_TRH_Gproc.pkFORSs{2}
         (* otsdef, five-index form.  T3 taught that dropping the MEMBERSHIP
            characterisation makes the freshness/uniq step unprovable and that
            the loss is invisible until that goal is attacked. *)
         /\ (forall (adx : adrs * dgst),
               adx \in FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
               <=>
               (exists (i j u v w : int),
                  0 <= i < size R_TRH_Gproc.skFORSs{2} /\ 0 <= j < l' /\
                  0 <= u < k /\ 0 <= v < a /\ 0 <= w < nr_nodesf (v + 1) /\
                  adx = nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (i * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1)
                           + u * (2 ^ a - 1)
                           + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)))
         /\ (forall (i j u v w : int),
               0 <= i < size R_TRH_Gproc.skFORSs{2} => 0 <= j < l' => 0 <= u < k =>
               0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
               nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                   (i * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                    + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
               = (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                              (v + 1) (u * nr_nodesf (v + 1) + w),
                  let lvs = fors_leaves_op_cube
                              (nth witness (nth witness R_TRH_Gproc.skFORSs{2} i) j) pp{2}
                              (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j) u in
                    DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                      (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                      (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w))))) v
                      (u * nr_nodesf v + 2 * w))
                    ++
                    DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                      (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                      (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w + 1))))) v
                      (u * nr_nodesf v + 2 * w + 1))))
         /\ uniq (unzip1 FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2})
         /\ all (fun (ad : adrs) => get_typeidx ad = trhftype /\ FTWES.get_thidx ad <> 0)
                (unzip1 FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2})
         /\ all (fun (ad : adrs) => get_typeidx ad = trcotype \/ FTWES.get_thidx ad = 0)
                FTWES.TRHC.O_THFC_Default.tws{2}
         /\ size FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
            = size R_TRH_Gproc.skFORSs{2} * l' * k * (2 ^ a - 1)
         /\ size R_TRH_Gproc.skFORSs{2} = size R_TRH_Gproc.pkFORSs{2}
         /\ size R_TRH_Gproc.skFORSs{2} <= nr_trees 0).
  - (* T2 OUTER BODY.  INV-D2 is the outer invariant plus the PARTIAL-ROW
       clauses for the in-progress skFORSl: a second otsdef disjunct and a
       partial nth-characterisation, both indexed at
       size skFORSs * l' * k * (t-1) + j * k * (t-1) + ...
       MM45 FORS_ES.ec:4915-4990, minus their leavess/nodess/rootss size
       conjuncts (we do not accumulate those lists). *)
    wp => /=.
    while (   ={skFORSl, pkFORSl}
           /\ ps0{1} = pp{2}
           /\ ps0{1} = FTWES.TRHC_TCR.O_SMDTTCR_Default.pp{2}
           /\ ps0{1} = FTWES.TRHC.O_THFC_Default.pp{2}
           /\ ad0{1} = adz
           /\ ad0{1} = R_TRH_Gproc.ad{2}
           /\ skFORSnt0{1} = R_TRH_Gproc.skFORSs{2}
           /\ pkFORSnt0{1} = R_TRH_Gproc.pkFORSs{2}
           /\ (forall (adx : adrs * dgst),
                 adx \in FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 <=>
                 (exists (i j u v w : int),
                    0 <= i < size R_TRH_Gproc.skFORSs{2} /\ 0 <= j < l' /\
                    0 <= u < k /\ 0 <= v < a /\ 0 <= w < nr_nodesf (v + 1) /\
                    adx = nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                            (i * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1)
                             + u * (2 ^ a - 1)
                             + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w))
                 \/
                 (exists (j u v w : int),
                    0 <= j < size skFORSl{2} /\ 0 <= u < k /\
                    0 <= v < a /\ 0 <= w < nr_nodesf (v + 1) /\
                    adx = nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                            (size R_TRH_Gproc.skFORSs{2} * l' * k * (2 ^ a - 1)
                             + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                             + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)))
           /\ (forall (i j u v w : int),
                 0 <= i < size R_TRH_Gproc.skFORSs{2} => 0 <= j < l' => 0 <= u < k =>
                 0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
                 nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     (i * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                      + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
                 = (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                                (v + 1) (u * nr_nodesf (v + 1) + w),
                    let lvs = fors_leaves_op_cube
                                (nth witness (nth witness R_TRH_Gproc.skFORSs{2} i) j) pp{2}
                                (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j) u in
                      DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                        (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                        (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w))))) v
                        (u * nr_nodesf v + 2 * w))
                      ++
                      DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                        (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                        (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w + 1))))) v
                        (u * nr_nodesf v + 2 * w + 1))))
           /\ (forall (j u v w : int),
                 0 <= j < size skFORSl{2} => 0 <= u < k =>
                 0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
                 nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     (size R_TRH_Gproc.skFORSs{2} * l' * k * (2 ^ a - 1)
                      + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                      + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
                 = (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                                   (size R_TRH_Gproc.skFORSs{2})) j)
                                (v + 1) (u * nr_nodesf (v + 1) + w),
                    let lvs = fors_leaves_op_cube (nth witness skFORSl{2} j) pp{2}
                                (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                                   (size R_TRH_Gproc.skFORSs{2})) j) u in
                      DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                        (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                           (size R_TRH_Gproc.skFORSs{2})) j)
                        (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w))))) v
                        (u * nr_nodesf v + 2 * w))
                      ++
                      DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                        (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                           (size R_TRH_Gproc.skFORSs{2})) j)
                        (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w + 1))))) v
                        (u * nr_nodesf v + 2 * w + 1))))
           /\ uniq (unzip1 FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2})
           /\ all (fun (ad : adrs) => get_typeidx ad = trhftype /\ FTWES.get_thidx ad <> 0)
                  (unzip1 FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2})
           /\ all (fun (ad : adrs) => get_typeidx ad = trcotype \/ FTWES.get_thidx ad = 0)
                  FTWES.TRHC.O_THFC_Default.tws{2}
           /\ size FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
              = size R_TRH_Gproc.skFORSs{2} * l' * k * (2 ^ a - 1)
                + size skFORSl{2} * k * (2 ^ a - 1)
           /\ size R_TRH_Gproc.skFORSs{2} = size R_TRH_Gproc.pkFORSs{2}
           /\ size R_TRH_Gproc.skFORSs{2} < nr_trees 0
           /\ size skFORSl{2} = size pkFORSl{2}
           /\ size skFORSl{2} <= l').
    * (* K-LOOP.  From here down, EVERY invariant must carry the growing ts
         stack -- this is where T3's shape is actively misleading: there ts grew
         once per keypair, here it grows k*(2^a-1) entries per keypair INSIDE
         these loops.  Both external reviewers converged on this independently. *)
      inline{2} 6.
      wp => /=.
      while (   ={skFORS, rootsk, skFORSl, pkFORSl}
             /\ ps0{1} = pp{2}
             /\ ps0{1} = FTWES.TRHC.O_THFC_Default.pp{2}
             /\ ps0{1} = FTWES.TRHC_TCR.O_SMDTTCR_Default.pp{2}
             /\ ad0{1} = adz
             /\ ad0{1} = R_TRH_Gproc.ad{2}
             /\ skFORSnt0{1} = R_TRH_Gproc.skFORSs{2}
             /\ pkFORSnt0{1} = R_TRH_Gproc.pkFORSs{2}
             /\ (forall (adx : adrs * dgst),
                   adx \in FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                   <=>
                      t2_memA FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                        (size R_TRH_Gproc.skFORSs{2}) adx
                   \/ t2_memB FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                        (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}) adx
                   \/ t2_memC FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                        (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                        (size rootsk{2}) adx)             /\ t2_nthA FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                  R_TRH_Gproc.ad{2} pp{2} R_TRH_Gproc.skFORSs{2}
                  (size R_TRH_Gproc.skFORSs{2})
             /\ t2_nthB FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                  R_TRH_Gproc.ad{2} pp{2} skFORSl{2}
                  (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
             /\ t2_nthC FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                  R_TRH_Gproc.ad{2} pp{2} skFORS{2}
                  (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}) (size rootsk{2})
             /\ t2_good FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                        FTWES.TRHC.O_THFC_Default.tws{2}
             /\ size FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                  = size R_TRH_Gproc.skFORSs{2} * l' * k * t2_span
                    + size skFORSl{2} * k * t2_span
                    + size rootsk{2} * t2_span
             /\ size R_TRH_Gproc.skFORSs{2} = size R_TRH_Gproc.pkFORSs{2}
             /\ size R_TRH_Gproc.skFORSs{2} < nr_trees 0
             /\ size skFORSl{2} = size pkFORSl{2}
             /\ size skFORSl{2} < l'
             /\ size rootsk{2} <= k).
      + (* A-LOOP.  Adds the layer-D stack: t2_memD/t2_nthD for the layers of
           the current tree already committed to ts, plus t2_ndst characterising
           the node rows built so far, plus the inlined root's parameters
           (ps1/adT0/leavest0/idxt) -- T3 lesson #2, tied to the right here from
           the start rather than discovered by a failing node body. *)
        wp => /=.
        while (   ={skFORS, nodest, leavest, rootsk, skFORSl, pkFORSl}
               /\ ps0{1} = pp{2}
               /\ ps0{1} = FTWES.TRHC.O_THFC_Default.pp{2}
               /\ ps0{1} = FTWES.TRHC_TCR.O_SMDTTCR_Default.pp{2}
               /\ ad0{1} = adz
               /\ ad0{1} = R_TRH_Gproc.ad{2}
               /\ skFORSnt0{1} = R_TRH_Gproc.skFORSs{2}
               /\ pkFORSnt0{1} = R_TRH_Gproc.pkFORSs{2}
               /\ ps1{1} = pp{2}
               /\ adT0{1} = t2_adT R_TRH_Gproc.ad{2}
                              (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
               /\ leavest0{1} = leavest{2}
               /\ idxt{1} = size rootsk{2}
               /\ (forall (adx : adrs * dgst),
                     adx \in FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     <=>
                        t2_memA FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (size R_TRH_Gproc.skFORSs{2}) adx
                     \/ t2_memB FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}) adx
                     \/ t2_memC FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                          (size rootsk{2}) adx
                     \/ t2_memD FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                          (size rootsk{2}) (size nodest{2}) adx)               /\ t2_nthA FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                    R_TRH_Gproc.ad{2} pp{2} R_TRH_Gproc.skFORSs{2}
                    (size R_TRH_Gproc.skFORSs{2})
               /\ t2_nthB FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                    R_TRH_Gproc.ad{2} pp{2} skFORSl{2}
                    (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
               /\ t2_nthC FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                    R_TRH_Gproc.ad{2} pp{2} skFORS{2}
                    (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}) (size rootsk{2})
               /\ t2_nthD FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                    R_TRH_Gproc.ad{2} pp{2} leavest{2}
                    (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                    (size rootsk{2}) (size nodest{2})
               /\ t2_ndst pp{2}
                    (t2_adT R_TRH_Gproc.ad{2}
                       (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}))
                    leavest{2} (size rootsk{2}) nodest{2}
               /\ t2_good FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          FTWES.TRHC.O_THFC_Default.tws{2}
               /\ size FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                    = size R_TRH_Gproc.skFORSs{2} * l' * k * t2_span
                      + size skFORSl{2} * k * t2_span
                      + size rootsk{2} * t2_span
                      + bigi predT (fun (m : int) => nr_nodesf m) 1 (size nodest{2} + 1)
               /\ size leavest{2} = t
               /\ size R_TRH_Gproc.skFORSs{2} = size R_TRH_Gproc.pkFORSs{2}
               /\ size R_TRH_Gproc.skFORSs{2} < nr_trees 0
               /\ size skFORSl{2} = size pkFORSl{2}
               /\ size skFORSl{2} < l'
               /\ size rootsk{2} < k
               /\ size nodest{2} <= a).
        - (* NODE-LOOP.  The deepest ts layer: t2_memE/t2_nthE for the nodes of
             the current layer already queried, and t2_ndscl for the partial row.
             This is the loop that actually appends to ts. *)
          wp => /=.
          while (   ={skFORS, nodescl, nodespl, nodest, leavest, rootsk,
                       skFORSl, pkFORSl}
                 /\ ps0{1} = pp{2}
                 /\ ps0{1} = FTWES.TRHC.O_THFC_Default.pp{2}
                 /\ ps0{1} = FTWES.TRHC_TCR.O_SMDTTCR_Default.pp{2}
                 /\ ad0{1} = adz
                 /\ ad0{1} = R_TRH_Gproc.ad{2}
                 /\ skFORSnt0{1} = R_TRH_Gproc.skFORSs{2}
                 /\ pkFORSnt0{1} = R_TRH_Gproc.pkFORSs{2}
                 /\ ps1{1} = pp{2}
                 /\ adT0{1} = t2_adT R_TRH_Gproc.ad{2}
                                (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                 /\ leavest0{1} = leavest{2}
                 /\ idxt{1} = size rootsk{2}
                 /\ nodespl{2} = last leavest{2} nodest{2}
                 /\ (forall (adx : adrs * dgst),
                       adx \in FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                       <=>
                          t2_memA FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                            (size R_TRH_Gproc.skFORSs{2}) adx
                       \/ t2_memB FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                            (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}) adx
                       \/ t2_memC FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                            (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                            (size rootsk{2}) adx
                       \/ t2_memD FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                            (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                            (size rootsk{2}) (size nodest{2}) adx
                       \/ t2_memE FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                            (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                            (size rootsk{2}) (size nodest{2})
                            (size nodescl{2}) adx)                 /\ t2_nthA FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                      R_TRH_Gproc.ad{2} pp{2} R_TRH_Gproc.skFORSs{2}
                      (size R_TRH_Gproc.skFORSs{2})
                 /\ t2_nthB FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                      R_TRH_Gproc.ad{2} pp{2} skFORSl{2}
                      (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                 /\ t2_nthC FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                      R_TRH_Gproc.ad{2} pp{2} skFORS{2}
                      (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}) (size rootsk{2})
                 /\ t2_nthD FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                      R_TRH_Gproc.ad{2} pp{2} leavest{2}
                      (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                      (size rootsk{2}) (size nodest{2})
                 /\ t2_nthE FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                      R_TRH_Gproc.ad{2} pp{2} leavest{2}
                      (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                      (size rootsk{2}) (size nodest{2}) (size nodescl{2})
                 /\ t2_ndst pp{2}
                      (t2_adT R_TRH_Gproc.ad{2}
                         (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}))
                      leavest{2} (size rootsk{2}) nodest{2}
                 /\ t2_ndscl pp{2}
                      (t2_adT R_TRH_Gproc.ad{2}
                         (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}))
                      leavest{2} (size rootsk{2}) (size nodest{2}) nodescl{2}
                 /\ t2_good FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                            FTWES.TRHC.O_THFC_Default.tws{2}
                 /\ size FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                      = size R_TRH_Gproc.skFORSs{2} * l' * k * t2_span
                        + size skFORSl{2} * k * t2_span
                        + size rootsk{2} * t2_span
                        + bigi predT (fun (m : int) => nr_nodesf m) 1 (size nodest{2} + 1)
                        + size nodescl{2}
                 /\ size leavest{2} = t
                 /\ size R_TRH_Gproc.skFORSs{2} = size R_TRH_Gproc.pkFORSs{2}
                 /\ size R_TRH_Gproc.skFORSs{2} < nr_trees 0
                 /\ size skFORSl{2} = size pkFORSl{2}
                 /\ size skFORSl{2} < l'
                 /\ size rootsk{2} < k
                 /\ size nodest{2} < a
                 /\ size nodescl{2} <= nr_nodesf (size nodest{2} + 1)).
          * (* T2 NODE-LOOP BODY -- the only loop that appends to ts.
               VERIFIED opening (probe, 0 errors):
                 inline{2} 3.
                 wp; skip => />.
               leaves a 20-hypothesis chain, and the named ops keep it legible:
               the hypotheses come through as t2_nthA/B/C/D/E, t2_ndst,
               t2_ndscl, t2_good and the partial-sum size conjunct rather than
               as five pages of nth-formulas.  That readability is the whole
               reason the op layer exists.

               CLOSED 2026-08-06.  The post splits into exactly ELEVEN
               conjuncts (measured by bisection: 17 admits succeed, 18 reports
               "all goals are closed"; 12-17 are this file's other pending
               obligations).  Each is now a citation:

                 1  otsdef   t2_otsdef_step      (membership, both directions)
                 2  nthA     t2_nthA_append
                 3  nthB     t2_nthB_append
                 4  nthC     t2_nthC_append
                 5  nthD     t2_nthD_append
                 6  nthE     t2_nthE_step        (CHALLENGE INPUT, via
                                                  node_children_step)
                 7  ndscl    t2_ndscl_step       (RETURNED node, via
                                                  node_level_step)
                 8  uniq     nodeaddr_notin_ts   (freshness vs ALL of ts)
                 9  all      nodeaddr_good
                 10 size     arithmetic
                 11 size     arithmetic

               The linchpin is `hsz`, and it is free: the invariant's size
               conjunct is SYNTACTICALLY t2_off unfolded, so `rewrite /t2_off;
               exact szts` discharges it.  That the two coincide is the payoff
               for naming the five-index layout as an op instead of writing it
               out -- had the invariant spelled the sum out differently, every
               one of the eleven would have needed its own normalisation.

               MUST-FAIL CONTROLS (all confirmed RC=1 for a PROOF reason, not a
               typing one):
                 * t2_otsdef_step without the memA (resp. memE) lifting step
                   -> cannot prove goal (strict);
                 * nodeaddr_notin_ts handed an OFF-BY-ONE memE bound in the old
                   membership -> cannot prove goal (strict).  This is the sharp
                   one: at wi+1 the old ts may already hold the address being
                   appended, so uniq is genuinely FALSE, not merely unproven;
                 * t2_nthE_step without t2_ndst -> cannot close goals;
                 * conjunct 1 without its `rewrite size_rcons` -> does not apply
                   (the goal's memE bound is `size (rcons nodescl _)`);
                 * conjunct 7's citation used for conjunct 6 -> type error.
               Two EARLIER attempts at controls passed when they should have
               failed, and the reason is worth recording: dropping a named
               hypothesis from an `apply` and leaving `_` proves nothing,
               because the trailing `smt` reads the whole local context and
               simply finds it again.  A control must delete the INFORMATION.

               RETRACTED (adversarial review, 2026-08-06).  This comment
               previously claimed the goal could not be dumped -- "times out at
               1500s AND 3000s" -- and prescribed a mirror-module refactor.
               BOTH WERE WRONG, and the cause was my own probe: the generator
               cut the file INSIDE this very comment, leaving an unterminated
               open-comment token, so `inline{2} 3; wp; skip` were swallowed by
               it and never
               ran.  EasyCrypt then HANGS on the unterminated comment instead of
               erroring, which is what I read as an expensive wp.

               With a comment-balanced probe the goal dumps in ~4 SECONDS.
               GPT-5.6 found this by reading _t3p.ec; I confirmed it directly
               (28 comment opens, 27 closes).  mk_probe2.py now enforces balance
               on its output and says so in its docstring.

               STANDING LESSON: never trust a timeout that is not accompanied by
               a goal.  A hang is evidence about the HARNESS until proven
               otherwise. *)
            inline{2} 3.
            wp; skip => />.
            move=> &2 otsdef nthA nthB nthC nthD nthE ndst ndscl uq allts alltws
                   szts eqt_szlfs eqszskpkfs lts_szskfs eqszskpkfl ltl_szskfl
                   ltk_szrsk lta_szndst lenn_szndscl ltnn_szndscl.
            have hsz : size FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     = t2_off (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                              (size rootsk{2}) (size nodest{2}) (size nodescl{2}).
            + by rewrite /t2_off; exact szts.
            do ! split.
            (* 1 otsdef -- size_rcons FIRST: the goal's memE bound is
               `size (rcons nodescl _)`, not `size nodescl + 1`. *)
            rewrite size_rcons.
            by apply (t2_otsdef_step _ (size R_TRH_Gproc.skFORSs{2})
                        (size skFORSl{2}) (size rootsk{2}) (size nodest{2})
                        (size nodescl{2}) _ hsz _ _ _ _ otsdef);
               smt(size_ge0).
            by apply (t2_nthA_append _ _ _ _ _ _ _ _ _ _ hsz) => //; smt(size_ge0 ge2_lp ge1_k ge1_a).
            by apply (t2_nthB_append _ _ _ _ _ _ _ _ _ _ hsz) => //; smt(size_ge0 ge2_lp ge1_k ge1_a).
            by apply (t2_nthC_append _ _ _ _ _ _ _ _ _ _ hsz) => //; smt(size_ge0 ge2_lp ge1_k ge1_a).
            by apply (t2_nthD_append _ _ _ _ _ _ _ _ _ _ hsz) => //; smt(size_ge0 ge2_lp ge1_k ge1_a).
            (* 6 nthE -- the CHALLENGE INPUT (node_children_step). *)
            rewrite size_rcons.
            by apply (t2_nthE_step _ _ leavest{2} nodest{2}
                        (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                        (size rootsk{2}) (size nodest{2}) (size nodescl{2})
                        hsz eqt_szlfs _ _ _ ndst nthE);
               smt(size_ge0).
            (* 7 ndscl -- the RETURNED node (node_level_step). *)
            by apply (t2_ndscl_step _ leavest{2} nodest{2} nodescl{2}
                        (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                        (size rootsk{2}) (size nodest{2})
                        eqt_szlfs _ _ ltnn_szndscl ndst ndscl);
               smt(size_ge0).
            (* 8 uniq -- freshness of the new address against ALL of ts. *)
            rewrite map_rcons /= rcons_uniq uq /=.
            by apply (nodeaddr_notin_ts _ FTWES.TRHC_TCR.O_SMDTTCR_Default.pp{2}
                        R_TRH_Gproc.skFORSs{2} skFORSl{2} skFORS{2} leavest{2}
                        (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                        (size rootsk{2}) (size nodest{2}) (size nodescl{2})
                        hsz _ _ _ _ _ otsdef nthA nthB nthC nthD nthE);
               smt(size_ge0).
            (* 9 all -- no all_rcons in the stdlib; go through -cats1/all_cat. *)
            rewrite map_rcons /= -cats1 all_cat allts /=.
            by apply (nodeaddr_good (size R_TRH_Gproc.skFORSs{2})
                        (size skFORSl{2}) (size rootsk{2}) (size nodest{2})
                        (size nodescl{2})); smt(size_ge0).
            by rewrite ?size_rcons szts; smt().
            by rewrite size_rcons; smt().
          (* T2 NODE-LOOP ENTRY+EXIT.  Two remaining assignments
               nodespl <- last leavest nodest ;  nodescl <- []
             so `wp; skip` first, then the pure obligation.

             ARITIES ARE MEASURED, NOT COUNTED.  `move=> />` does NOTHING here
             (the goal opens `forall &1 &2` -- the two dumps were byte-identical),
             so this uses T3's `[#]` form, which is also the only way to flatten
             a conjunction that deep given that EasyCrypt's `/\` intro patterns
             are strictly binary.  pre = 36, exit = 38, each found by supplying
             45 names ONE PER LINE and reading the line number back out of the
             "nothing to introduce" error.  An earlier pass on this file guessed
             19 where the truth was 15 and every later name was silently off by
             four, which made a goal LOOK like a repeated loop. *)
          wp; skip => &1 &2 [#] p01 p02 p03 p04 p05 p06 p07 p08 p09 p10
                                p11 p12 p13 p14 p15 p16 p17 p18 p19 p20
                                p21 p22 p23 p24 p25 p26 p27 p28 p29 p30
                                p31 p32 p33 p34 p35 p36.
          split.
          + (* ENTRY.  nodescl starts [], so the memE / nthE / ndscl layers are
               vacuous and the 5-disjunct node invariant collapses onto the
               4-disjunct a-loop one that p18 already gives. *)
            split; last by rewrite p02.
            (* The hint list is load-bearing AS A SET -- bare `smt()` returns
               "cannot prove goal (strict)".  But t2_memE_nil INDIVIDUALLY is
               not: dropping it still compiles, because t2_memE is a transparent
               op and smt unfolds it and sees the empty range itself.  Stated
               precisely because a hint that is merely present is not evidence
               of anything; it is kept for symmetry with the other two, which
               ARE needed. *)
            by rewrite /=; smt(t2_memE_nil t2_nthE_nil t2_ndscl_nil expr_gt0 size_ge0).
          (* EXIT.  The guard gives `! (size nodesclR < nr_nodesf (size nodest+1))`
             and the invariant gives `<=`, so the level is EXACTLY full -- that
             equality is what lets all four fold lemmas fire.  Note the goal
             writes `size (rcons nodest nodesclR)` everywhere and never
             `size nodest + 1`; the folds are stated at `+ 1`, so hnd must
             normalise FIRST (same lesson as size_rcons in the body). *)
          move=> nodesclL tsR nodesclR hgL hgR [#]
                 e01 e02 e03 e04 e05 e06 e07 e08 e09 e10
                 e11 e12 e13 e14 e15 e16 e17 e18 e19 e20
                 e21 e22 e23 e24 e25 e26 e27 e28 e29 e30
                 e31 e32 e33 e34 e35 e36 e37 e38.
          have hfull : size nodesclR = nr_nodesf (size nodest{2} + 1) by smt().
          have hnd : size (rcons nodest{2} nodesclR) = size nodest{2} + 1
            by rewrite size_rcons.
          (* Derive the FOUR folded atoms up front.  One `smt` over the whole
             32-conjunct post does NOT work -- it spends two minutes and returns
             "cannot prove goal (strict)" -- because it has to invent the fold
             instantiations.  Handing it the finished atoms leaves it nothing to
             do but match. *)
          have hmem : forall (adx : adrs * dgst),
              adx \in tsR <=>
              (t2_memA tsR (size R_TRH_Gproc.skFORSs{2}) adx
               \/ t2_memB tsR (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}) adx
               \/ t2_memC tsR (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                    (size rootsk{2}) adx
               \/ t2_memD tsR (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                    (size rootsk{2}) (size nodest{2} + 1) adx).
          + move=> adx; have h := e21 adx; rewrite hfull in h.
            rewrite (t2_memD_fold tsR (size R_TRH_Gproc.skFORSs{2})
                       (size skFORSl{2}) (size rootsk{2}) (size nodest{2}) adx _);
              1: smt(size_ge0).
            smt().
          have hnthD : t2_nthD tsR R_TRH_Gproc.ad{2} pp{2} leavest{2}
              (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}) (size rootsk{2})
              (size nodest{2} + 1).
          + apply (t2_nthD_fold tsR R_TRH_Gproc.ad{2} pp{2} leavest{2}
                     (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                     (size rootsk{2}) (size nodest{2})).
            - smt(size_ge0).
            - exact e25.
            by rewrite -hfull; exact e26.
          have hndst : t2_ndst pp{2}
              (t2_adT R_TRH_Gproc.ad{2} (size R_TRH_Gproc.skFORSs{2})
                 (size skFORSl{2})) leavest{2} (size rootsk{2})
              (rcons nodest{2} nodesclR).
          + by apply (t2_ndst_fold pp{2} (t2_adT R_TRH_Gproc.ad{2}
                        (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}))
                        leavest{2} (size rootsk{2}) nodest{2} nodesclR
                        e27 e28 hfull).
          have hszts : size tsR
              = size R_TRH_Gproc.skFORSs{2} * l' * k * t2_span
                + size skFORSl{2} * k * t2_span + size rootsk{2} * t2_span
                + bigi predT (fun (m : int) => nr_nodesf m) 1
                    (size nodest{2} + 1 + 1).
          + by rewrite (bigi_nnf_recr (size nodest{2})) 1:size_ge0 e30 hfull; ring.
          split; last by rewrite !size_rcons e04.
          rewrite hnd.
          by do ! split; smt().
        (* LEAF LOOP.  Sits between `leavest <- []` and the a-loop, so `while`
           reaches it only after the a-loop is discharged (backwards reasoning).

           IT DOES NOT TOUCH ts.  Verified at the source (see t2_good): the leaf
           step is `OC.query`, the COLLECTION oracle, so it extends `tws` and
           `leavest` only.  So the whole ts stack -- otsdef at memA/memB/memC
           depth, nthA/nthB/nthC, t2_good, the size conjunct -- rides through
           UNCHANGED, and this loop is materially simpler than the node loop.
           `nodest` does not exist yet, which is why there is no memD/nthD layer
           and no t2_ndst here.

           The one moving part is `leavest`, carried in MM45's own prefix form
           (FORS_ES.ec:5676): a `mkseq` over the leaf op, NOT `take` of
           fors_leaves_op_cube.  That choice is what makes the a-loop exit work
           later -- T3 converts exactly this hypothesis with `cube_is_mkseq`
           (GprocVI.ec:26, and _t3head.ec:7 for the usage), and the conversion
           happens in the COMBINED exit goal below, where the leaf loop's
           hypothesis is still in scope.  So the a-loop invariant does NOT need
           a `leavest = fors_leaves_op_cube ..` conjunct, and none of the closed
           loops above have to be reopened. *)
        wp => /=.
        while (   ={skFORS, leavest, rootsk, skFORSl, pkFORSl}
               /\ ps0{1} = pp{2}
               /\ ps0{1} = FTWES.TRHC.O_THFC_Default.pp{2}
               /\ ps0{1} = FTWES.TRHC_TCR.O_SMDTTCR_Default.pp{2}
               /\ ad0{1} = adz
               /\ ad0{1} = R_TRH_Gproc.ad{2}
               /\ skFORSnt0{1} = R_TRH_Gproc.skFORSs{2}
               /\ pkFORSnt0{1} = R_TRH_Gproc.pkFORSs{2}
               /\ leavest{2}
                  = mkseq (fun (m : int) =>
                       f pp{2}
                         (set_thtbidx (t2_adT R_TRH_Gproc.ad{2}
                             (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}))
                            0 (size rootsk{2} * t + m))
                         (DigestBlock.val (nth witness (nth witness
                            (FTWES.DBLLKTL.val skFORS{2}) (size rootsk{2})) m)))
                      (size leavest{2})
               /\ (forall (adx : adrs * dgst),
                     adx \in FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     <=>
                        t2_memA FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (size R_TRH_Gproc.skFORSs{2}) adx
                     \/ t2_memB FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}) adx
                     \/ t2_memC FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                          (size rootsk{2}) adx)
               /\ t2_nthA FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                    R_TRH_Gproc.ad{2} pp{2} R_TRH_Gproc.skFORSs{2}
                    (size R_TRH_Gproc.skFORSs{2})
               /\ t2_nthB FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                    R_TRH_Gproc.ad{2} pp{2} skFORSl{2}
                    (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
               /\ t2_nthC FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                    R_TRH_Gproc.ad{2} pp{2} skFORS{2}
                    (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}) (size rootsk{2})
               /\ t2_good FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          FTWES.TRHC.O_THFC_Default.tws{2}
               /\ size FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                    = size R_TRH_Gproc.skFORSs{2} * l' * k * t2_span
                      + size skFORSl{2} * k * t2_span
                      + size rootsk{2} * t2_span
               /\ size R_TRH_Gproc.skFORSs{2} = size R_TRH_Gproc.pkFORSs{2}
               /\ size R_TRH_Gproc.skFORSs{2} < nr_trees 0
               /\ size skFORSl{2} = size pkFORSl{2}
               /\ size skFORSl{2} < l'
               /\ size rootsk{2} < k
               /\ size leavest{2} <= t).
        - (* LEAF-LOOP BODY.  16 hypotheses (measured).  Three real obligations:
             the two sides agree once `f` is unfolded to `thfc n` (the inlined
             OC.query writes `thfc (size x)`, and DigestBlock.valP turns that
             size into n); the mkseq extends by one via mkseqS; and `tws` gains
             the leaf address, whose predicate is discharged by leafaddr_thidx0
             taking the get_thidx = 0 disjunct.  The whole ts stack (b02..b07,
             b09) is untouched -- OC.query is the COLLECTION oracle. *)
          inline{2} 1.
          wp; skip => /> &2 b01 b02 b03 b04 b05 b06 b07 b08 b09 b10 b11 b12
                            b13 b14 b15 b16.
          rewrite /f DigestBlock.valP ?size_rcons.
          rewrite (mkseqS _ (size leavest{2})) 1:size_ge0 -b01.
          rewrite -?cats1 ?all_cat b08 /=.
          smt(leafaddr_thidx0 size_ge0).
        (* LEAF-EXIT + a-LOOP ENTRY+EXIT.  `while` folds each exit into the
           remaining goal's post, so this ONE goal carries THREE obligations
           nested two deep -- the leaf loop's entry, then under the leaf-exit
           hypotheses the a-loop's entry, then under the a-exit hypotheses the
           k-loop's step.  Same shape T3 documented at _t3.ec:842.

           ARITIES MEASURED: pre 24, leaf-exit 25, a-exit 32.  T3's were 19/15/15
           and are NOT reusable -- our invariants carry the ts stack and T3's
           did not. *)
        wp; skip => &1 &2 [#]
                              q01 q02 q03 q04 q05 q06 q07 q08 q09 q10 q11 
                              q12 q13 q14 q15 q16 q17 q18 q19 q20 q21 q22 
                              q23 q24.
        (* LEAF ENTRY: leavest starts [], and mkseq _ 0 = []. *)
        split; 1: by rewrite mkseq0 /=; smt(ge2_t size_ge0).
        move=> lfL twsR lfR hL hR [#]
               r01 r02 r03 r04 r05 r06 r07 r08 r09 r10 r11 r12 r13 r14 r15 
               r16 r17 r18 r19 r20 r21 r22 r23 r24 r25.
        (* A ENTRY: nodest starts [], so the memD / nthD / ndst layers are
           vacuous and the 4-disjunct a-loop invariant collapses onto the
           3-disjunct k-loop one.  The adT0 conjunct is just t2_adT unfolded
           against the q-equalities. *)
        split; 1: by rewrite /t2_adT /=;
                    smt(t2_memD_nil t2_nthD_nil t2_ndst_nil bigi_nnf_nil
                        size_ge0 ge1_a).
        (* twsR2 is the TS list, not tws -- the a-loop's right side extends
           O_SMDTTCR_Default.ts.  Name kept for continuity with the leaf-exit
           binder above; flagged by adversarial review as misleading, and it is:
           every use below reads it as ts. *)
        move=> ndL twsR2 ndR gL gR [#]
               s01 s02 s03 s04 s05 s06 s07 s08 s09 s10 s11 s12 s13 s14 s15 
               s16 s17 s18 s19 s20 s21 s22 s23 s24 s25 s26 s27 s28 s29 s30 
               s31 s32.
        (* A-LOOP EXIT.  Simpler than expected: BOTH sides append the same
           expression `nth (nth nodest (a-1)) 0`, so the roots agree from
           ndL = ndR alone and root_from_nodest is NOT needed here.

           This is where the leaf loop finally pays: hlfR converts the leaf
           loop's mkseq into fors_leaves_op_cube via cube_is_mkseq, and
           t2_nthC_fold consumes exactly that to turn the D-layer (which speaks
           of the leaf list) into the C-layer (which speaks of skFORS).  It is
           also where sum_nr_nodesf pays, inside t2_size_fold_a.

           As at the node exit, the three folded atoms are derived UP FRONT --
           one smt over the whole post has to invent the fold instantiations and
           does not converge. *)
        (* CONTROLS on this exit, graded by FAILURE REASON, not exit code:
             F3  t2_nthC_fold handed a VACUOUS D-layer (0 for a)
                 -> cannot prove goal (strict).  Proof-level: the fold really
                 does need every layer of the finished tree.
             F2  t2_nthC_fold's cube premise weakened to `size lvs = t`
                 -> nothing to rewrite.  Structural, but it is the empirical
                 answer to the design question that opened this section: an
                 arbitrary length-t list does NOT suffice, the leaf loop's
                 actual postcondition is required.
             F1  `size ndR = a` weakened to `<=`  -> nothing to rewrite.
             F4  t2_size_fold_a's sum truncated to a -> nothing to rewrite.
           F1/F2/F4 are structural because an exit proof is a rewrite chain;
           only F3 reaches the solver.  Recorded rather than presented as four
           equal controls. *)
        have hszlf : size lfR = t by smt().
        have hlfR : lfR = fors_leaves_op_cube skFORS{2} pp{2}
              (t2_adT R_TRH_Gproc.ad{2} (size R_TRH_Gproc.skFORSs{2})
                 (size skFORSl{2})) (size rootsk{2}).
        + by rewrite cube_is_mkseq r13 hszlf.
        have hnda : size ndR = a by smt().
        have hrk : size (rcons rootsk{2} (nth witness (nth witness ndR (a - 1)) 0))
                 = size rootsk{2} + 1 by rewrite size_rcons.
        have hmem : forall (adx : adrs * dgst),
            adx \in twsR2 <=>
            (t2_memA twsR2 (size R_TRH_Gproc.skFORSs{2}) adx
             \/ t2_memB twsR2 (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}) adx
             \/ t2_memC twsR2 (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                  (size rootsk{2} + 1) adx).
        + move=> adx; have h := s18 adx; rewrite hnda in h.
          rewrite (t2_memC_fold twsR2 (size R_TRH_Gproc.skFORSs{2})
                     (size skFORSl{2}) (size rootsk{2}) adx _); 1: smt(size_ge0).
          smt().
        have hnthC : t2_nthC twsR2 R_TRH_Gproc.ad{2} pp{2} skFORS{2}
            (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2}) (size rootsk{2} + 1).
        + apply (t2_nthC_fold twsR2 R_TRH_Gproc.ad{2} pp{2} skFORS{2} lfR
                   (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})
                   (size rootsk{2})).
          - smt(size_ge0).
          - exact hlfR.
          - exact s21.
          by rewrite -hnda; exact s22.
        have hszts : size twsR2
            = size R_TRH_Gproc.skFORSs{2} * l' * k * t2_span
              + size skFORSl{2} * k * t2_span + (size rootsk{2} + 1) * t2_span.
        + by rewrite -t2_size_fold_a -hnda; exact s25.
        split; last by rewrite !size_rcons s04.
        rewrite hrk.
        by do ! split; smt().
      (* K-LOOP ENTRY+EXIT.  The goal does NOT start at the loop: four
         statements precede it, code-identical on both sides --
           skFORScube <- [] ; the two-deep sampling keygen ; skFORS <- insubd
           skFORScube ; rootsk <- []
         so the skFORS keygen block is dispatched first with `seq 2 2` and a
         frame, exactly as T3 does (_t3.ec:916).

         The frame is the l'-loop invariant VERBATIM, emitted by
         scratch/mk_kframe.py which extracts it from this file by paren-matching
         -- 82 lines of nested `let`s and index arithmetic that must agree
         EXACTLY with the `while` above, so transcribing it by hand is a drift
         hazard for no benefit.

         `sim` will NOT do this: it takes its argument as the WHOLE relational
         invariant, so the pre survives only through what that invariant
         implies -- pass `={skFORScube}` alone and the leftover has no
         `size skFORSl{2} < l'` to draw on. *)
      seq 2 2 : (   ={skFORScube}
                 /\ ={skFORSl, pkFORSl}
                 /\ ps0{1} = pp{2}
                 /\ ps0{1} = FTWES.TRHC_TCR.O_SMDTTCR_Default.pp{2}
                 /\ ps0{1} = FTWES.TRHC.O_THFC_Default.pp{2}
                 /\ ad0{1} = adz
                 /\ ad0{1} = R_TRH_Gproc.ad{2}
                 /\ skFORSnt0{1} = R_TRH_Gproc.skFORSs{2}
                 /\ pkFORSnt0{1} = R_TRH_Gproc.pkFORSs{2}
                 /\ (forall (adx : adrs * dgst),
                 adx \in FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 <=>
                 (exists (i j u v w : int),
                 0 <= i < size R_TRH_Gproc.skFORSs{2} /\ 0 <= j < l' /\
                 0 <= u < k /\ 0 <= v < a /\ 0 <= w < nr_nodesf (v + 1) /\
                 adx = nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 (i * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1)
                 + u * (2 ^ a - 1)
                 + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w))
                 \/
                 (exists (j u v w : int),
                 0 <= j < size skFORSl{2} /\ 0 <= u < k /\
                 0 <= v < a /\ 0 <= w < nr_nodesf (v + 1) /\
                 adx = nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRH_Gproc.skFORSs{2} * l' * k * (2 ^ a - 1)
                 + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                 + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)))
                 /\ (forall (i j u v w : int),
                 0 <= i < size R_TRH_Gproc.skFORSs{2} => 0 <= j < l' => 0 <= u < k =>
                 0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
                 nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 (i * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                 + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
                 = (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                 (v + 1) (u * nr_nodesf (v + 1) + w),
                 let lvs = fors_leaves_op_cube
                 (nth witness (nth witness R_TRH_Gproc.skFORSs{2} i) j) pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j) u in
                 DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                 (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w))))) v
                 (u * nr_nodesf v + 2 * w))
                 ++
                 DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                 (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w + 1))))) v
                 (u * nr_nodesf v + 2 * w + 1))))
                 /\ (forall (j u v w : int),
                 0 <= j < size skFORSl{2} => 0 <= u < k =>
                 0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
                 nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRH_Gproc.skFORSs{2} * l' * k * (2 ^ a - 1)
                 + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                 + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
                 = (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                 (size R_TRH_Gproc.skFORSs{2})) j)
                 (v + 1) (u * nr_nodesf (v + 1) + w),
                 let lvs = fors_leaves_op_cube (nth witness skFORSl{2} j) pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                 (size R_TRH_Gproc.skFORSs{2})) j) u in
                 DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                 (size R_TRH_Gproc.skFORSs{2})) j)
                 (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w))))) v
                 (u * nr_nodesf v + 2 * w))
                 ++
                 DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                 (size R_TRH_Gproc.skFORSs{2})) j)
                 (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w + 1))))) v
                 (u * nr_nodesf v + 2 * w + 1))))
                 /\ uniq (unzip1 FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2})
                 /\ all (fun (ad : adrs) => get_typeidx ad = trhftype /\ FTWES.get_thidx ad <> 0)
                 (unzip1 FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2})
                 /\ all (fun (ad : adrs) => get_typeidx ad = trcotype \/ FTWES.get_thidx ad = 0)
                 FTWES.TRHC.O_THFC_Default.tws{2}
                 /\ size FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 = size R_TRH_Gproc.skFORSs{2} * l' * k * (2 ^ a - 1)
                 + size skFORSl{2} * k * (2 ^ a - 1)
                 /\ size R_TRH_Gproc.skFORSs{2} = size R_TRH_Gproc.pkFORSs{2}
                 /\ size R_TRH_Gproc.skFORSs{2} < nr_trees 0
                 /\ size skFORSl{2} = size pkFORSl{2}
                 /\ size skFORSl{2} <= l'
                 /\ size skFORSl{1} < l'
                 /\ size skFORSl{2} < l').
      + while (   ={skFORScube}
                 /\ ={skFORSl, pkFORSl}
                 /\ ps0{1} = pp{2}
                 /\ ps0{1} = FTWES.TRHC_TCR.O_SMDTTCR_Default.pp{2}
                 /\ ps0{1} = FTWES.TRHC.O_THFC_Default.pp{2}
                 /\ ad0{1} = adz
                 /\ ad0{1} = R_TRH_Gproc.ad{2}
                 /\ skFORSnt0{1} = R_TRH_Gproc.skFORSs{2}
                 /\ pkFORSnt0{1} = R_TRH_Gproc.pkFORSs{2}
                 /\ (forall (adx : adrs * dgst),
                 adx \in FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 <=>
                 (exists (i j u v w : int),
                 0 <= i < size R_TRH_Gproc.skFORSs{2} /\ 0 <= j < l' /\
                 0 <= u < k /\ 0 <= v < a /\ 0 <= w < nr_nodesf (v + 1) /\
                 adx = nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 (i * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1)
                 + u * (2 ^ a - 1)
                 + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w))
                 \/
                 (exists (j u v w : int),
                 0 <= j < size skFORSl{2} /\ 0 <= u < k /\
                 0 <= v < a /\ 0 <= w < nr_nodesf (v + 1) /\
                 adx = nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRH_Gproc.skFORSs{2} * l' * k * (2 ^ a - 1)
                 + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                 + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)))
                 /\ (forall (i j u v w : int),
                 0 <= i < size R_TRH_Gproc.skFORSs{2} => 0 <= j < l' => 0 <= u < k =>
                 0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
                 nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 (i * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                 + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
                 = (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                 (v + 1) (u * nr_nodesf (v + 1) + w),
                 let lvs = fors_leaves_op_cube
                 (nth witness (nth witness R_TRH_Gproc.skFORSs{2} i) j) pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j) u in
                 DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                 (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w))))) v
                 (u * nr_nodesf v + 2 * w))
                 ++
                 DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                 (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w + 1))))) v
                 (u * nr_nodesf v + 2 * w + 1))))
                 /\ (forall (j u v w : int),
                 0 <= j < size skFORSl{2} => 0 <= u < k =>
                 0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
                 nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRH_Gproc.skFORSs{2} * l' * k * (2 ^ a - 1)
                 + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                 + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
                 = (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                 (size R_TRH_Gproc.skFORSs{2})) j)
                 (v + 1) (u * nr_nodesf (v + 1) + w),
                 let lvs = fors_leaves_op_cube (nth witness skFORSl{2} j) pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                 (size R_TRH_Gproc.skFORSs{2})) j) u in
                 DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                 (size R_TRH_Gproc.skFORSs{2})) j)
                 (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w))))) v
                 (u * nr_nodesf v + 2 * w))
                 ++
                 DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                 (size R_TRH_Gproc.skFORSs{2})) j)
                 (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w + 1))))) v
                 (u * nr_nodesf v + 2 * w + 1))))
                 /\ uniq (unzip1 FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2})
                 /\ all (fun (ad : adrs) => get_typeidx ad = trhftype /\ FTWES.get_thidx ad <> 0)
                 (unzip1 FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2})
                 /\ all (fun (ad : adrs) => get_typeidx ad = trcotype \/ FTWES.get_thidx ad = 0)
                 FTWES.TRHC.O_THFC_Default.tws{2}
                 /\ size FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 = size R_TRH_Gproc.skFORSs{2} * l' * k * (2 ^ a - 1)
                 + size skFORSl{2} * k * (2 ^ a - 1)
                 /\ size R_TRH_Gproc.skFORSs{2} = size R_TRH_Gproc.pkFORSs{2}
                 /\ size R_TRH_Gproc.skFORSs{2} < nr_trees 0
                 /\ size skFORSl{2} = size pkFORSl{2}
                 /\ size skFORSl{2} <= l'
                 /\ size skFORSl{1} < l'
                 /\ size skFORSl{2} < l').
        - wp; while (   ={skFORScube, skFORSet}
                 /\ ={skFORSl, pkFORSl}
                 /\ ps0{1} = pp{2}
                 /\ ps0{1} = FTWES.TRHC_TCR.O_SMDTTCR_Default.pp{2}
                 /\ ps0{1} = FTWES.TRHC.O_THFC_Default.pp{2}
                 /\ ad0{1} = adz
                 /\ ad0{1} = R_TRH_Gproc.ad{2}
                 /\ skFORSnt0{1} = R_TRH_Gproc.skFORSs{2}
                 /\ pkFORSnt0{1} = R_TRH_Gproc.pkFORSs{2}
                 /\ (forall (adx : adrs * dgst),
                 adx \in FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 <=>
                 (exists (i j u v w : int),
                 0 <= i < size R_TRH_Gproc.skFORSs{2} /\ 0 <= j < l' /\
                 0 <= u < k /\ 0 <= v < a /\ 0 <= w < nr_nodesf (v + 1) /\
                 adx = nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 (i * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1)
                 + u * (2 ^ a - 1)
                 + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w))
                 \/
                 (exists (j u v w : int),
                 0 <= j < size skFORSl{2} /\ 0 <= u < k /\
                 0 <= v < a /\ 0 <= w < nr_nodesf (v + 1) /\
                 adx = nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRH_Gproc.skFORSs{2} * l' * k * (2 ^ a - 1)
                 + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                 + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)))
                 /\ (forall (i j u v w : int),
                 0 <= i < size R_TRH_Gproc.skFORSs{2} => 0 <= j < l' => 0 <= u < k =>
                 0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
                 nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 (i * l' * k * (2 ^ a - 1) + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                 + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
                 = (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                 (v + 1) (u * nr_nodesf (v + 1) + w),
                 let lvs = fors_leaves_op_cube
                 (nth witness (nth witness R_TRH_Gproc.skFORSs{2} i) j) pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j) u in
                 DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                 (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w))))) v
                 (u * nr_nodesf v + 2 * w))
                 ++
                 DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype) i) j)
                 (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w + 1))))) v
                 (u * nr_nodesf v + 2 * w + 1))))
                 /\ (forall (j u v w : int),
                 0 <= j < size skFORSl{2} => 0 <= u < k =>
                 0 <= v < a => 0 <= w < nr_nodesf (v + 1) =>
                 nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRH_Gproc.skFORSs{2} * l' * k * (2 ^ a - 1)
                 + j * k * (2 ^ a - 1) + u * (2 ^ a - 1)
                 + bigi predT (fun (m : int) => nr_nodesf m) 1 (v + 1) + w)
                 = (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                 (size R_TRH_Gproc.skFORSs{2})) j)
                 (v + 1) (u * nr_nodesf (v + 1) + w),
                 let lvs = fors_leaves_op_cube (nth witness skFORSl{2} j) pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                 (size R_TRH_Gproc.skFORSs{2})) j) u in
                 DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                 (size R_TRH_Gproc.skFORSs{2})) j)
                 (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w))))) v
                 (u * nr_nodesf v + 2 * w))
                 ++
                 DigestBlock.val (FTWES.val_bt_trh_gen pp{2}
                 (set_kpidx (set_tidx (set_typeidx R_TRH_Gproc.ad{2} trhftype)
                 (size R_TRH_Gproc.skFORSs{2})) j)
                 (oget (sub_bt (list2tree lvs) (rev (int2bs (a - v) (2 * w + 1))))) v
                 (u * nr_nodesf v + 2 * w + 1))))
                 /\ uniq (unzip1 FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2})
                 /\ all (fun (ad : adrs) => get_typeidx ad = trhftype /\ FTWES.get_thidx ad <> 0)
                 (unzip1 FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2})
                 /\ all (fun (ad : adrs) => get_typeidx ad = trcotype \/ FTWES.get_thidx ad = 0)
                 FTWES.TRHC.O_THFC_Default.tws{2}
                 /\ size FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 = size R_TRH_Gproc.skFORSs{2} * l' * k * (2 ^ a - 1)
                 + size skFORSl{2} * k * (2 ^ a - 1)
                 /\ size R_TRH_Gproc.skFORSs{2} = size R_TRH_Gproc.pkFORSs{2}
                 /\ size R_TRH_Gproc.skFORSs{2} < nr_trees 0
                 /\ size skFORSl{2} = size pkFORSl{2}
                 /\ size skFORSl{2} <= l'
                 /\ size skFORSl{1} < l'
                 /\ size skFORSl{2} < l').
          * by auto.
          by auto.
        by auto.
      (* Two statements remain (skFORS <- insubd skFORScube ; rootsk <- []),
         so `wp; skip` then the pure obligation.  pre = 25, MEASURED AFTER the
         layout repair -- the first measurement said 22 and was taken against
         the keygen while's goal, because a joined line had made the probe's
         marker cut swallow the frame's final `by auto.`. *)
      wp; skip => &1 &2 [#]
                            m01 m02 m03 m04 m05 m06 m07 m08 m09 m10 m11 m12 
                            m13 m14 m15 m16 m17 m18 m19 m20 m21 m22 m23 m24 
                            m25.
      (* K ENTRY: rootsk starts [], so the memC / nthC layers are vacuous and
         the 3-disjunct k-loop invariant collapses onto the 2-disjunct l'-loop
         one.  This is also the RAW <-> OP seam: the hypotheses arrive in the
         longhand form the l'-loop invariant is written in while the goal is
         op-phrased, and STEP 18's bridges are what connect them. *)
      split; 1: by rewrite /=;
                  smt(t2_memA_raw t2_memB_raw t2_nthA_raw t2_nthB_raw
                      t2_memC_nil t2_nthC_nil size_ge0 ge1_k).
      (* K-LOOP EXIT.  exit = 22 (measured).  Same shape as the a-exit one
         level up: the guard plus the invariant pin size rkR = k exactly, and
         that equality is what makes the B-level folds fire.

         The post is in the l'-loop invariant's LONGHAND form while the folds
         produce op form, so the goal is carried across STEP 18's seam with
         `-t2_*_raw` before the final assembly.  The pkFORSl conjunct needs
         /trco: the left side writes `trco ps ad x`, the inlined right side
         writes `thfc (size x) pp ad x`, and they are the same by definition. *)
      move=> rkL twsR tsR rkR gL gR [#]
             n01 n02 n03 n04 n05 n06 n07 n08 n09 n10 n11 n12 n13 n14 n15 
             n16 n17 n18 n19 n20 n21 n22.
      have hk : size rkR = k by smt().
      have hsl : size (rcons skFORSl{2} m24) = size skFORSl{2} + 1
        by rewrite size_rcons.
      have hmem : forall (adx : adrs * dgst),
          adx \in tsR <=>
          (t2_memA tsR (size R_TRH_Gproc.skFORSs{2}) adx
           \/ t2_memB tsR (size R_TRH_Gproc.skFORSs{2})
                (size skFORSl{2} + 1) adx).
      + move=> adx; have h := n12 adx; rewrite hk in h.
        rewrite (t2_memB_fold tsR (size R_TRH_Gproc.skFORSs{2})
                   (size skFORSl{2}) adx _); 1: smt(size_ge0).
        smt().
      have hnthB : t2_nthB tsR R_TRH_Gproc.ad{2} pp{2}
          (rcons skFORSl{2} m24) (size R_TRH_Gproc.skFORSs{2})
          (size skFORSl{2} + 1).
      + apply (t2_nthB_fold tsR R_TRH_Gproc.ad{2} pp{2} skFORSl{2} m24
                 (size R_TRH_Gproc.skFORSs{2}) (size skFORSl{2})).
        - done.
        - exact n14.
        by rewrite -hk; exact n15.
      have hszts : size tsR
          = size R_TRH_Gproc.skFORSs{2} * l' * k * t2_span
            + (size skFORSl{2} + 1) * k * t2_span.
      + (* NOT a global `-hk` here: k occurs in the l' and j terms too, so
           rewriting it
           globally would move all three.  Rewrite inside the hypothesis. *)
        have h := n17; rewrite hk in h.
        by rewrite -t2_size_fold_k; exact h.
      (* hszts is phrased with t2_span; the l'-loop invariant spells it out as
         (2 ^ a - 1), and smt will not unfold a defined op to bridge that. *)
      rewrite /t2_span in hszts.
      split; last by rewrite !size_rcons n03.
      (* The bridges CANNOT be applied with `rewrite` here: they quantify over
         `adx`, and in this goal `adx` is bound by a `forall`, so the rewrite
         would have to capture it.  Hand them to smt as hints instead -- the
         k-entry above crosses the same seam the same way. *)
      rewrite ?size_rcons /trco (size_flatten_roots rkR hk).
      (* Twenty conjuncts, handled in order.  A blanket `smt` with the bridges
         as hints does NOT work, and the reason is worth naming: for the nth
         conjuncts the bridge's right-hand side is a CLOSED `forall`, so
         `rewrite -t2_nth*_raw` matches the conjunct outright; but the mem
         bridge quantifies `adx` OUTSIDE, and in the goal `adx` is bound, so it
         can only be used after `move=> adx` brings the binder into scope. *)
      do ! split.
      + by rewrite n03 n01.
      + by smt().
      + by smt().
      + by smt().
      + by smt().
      + by smt().
      + by smt().
      + by smt().
      + by smt().
      + by move=> adx; rewrite -t2_memA_raw -t2_memB_raw; exact (hmem adx).
      (* NOT `rewrite -t2_nth*_raw`: those bridges keep the l'-invariant's
         `let lvs = .. in ..`, while the goal here has it SUBSTITUTED, so the
         pattern does not match.  Unfolding the hypothesis instead lands
         directly in the goal's form -- the ops contain no `let`. *)
      + by move: n13;
           rewrite /t2_nthA /t2_entry_sk /t2_entry_lvs /t2_pre /t2_off
                   /t2_span /t2_adT.
      + by move: hnthB;
           rewrite /t2_nthB /t2_entry_sk /t2_entry_lvs /t2_pre /t2_off
                   /t2_span /t2_adT.
      + by move: n16; rewrite /t2_good; smt().
      + by move: n16; rewrite /t2_good; smt().
      + (* CONJUNCT 15.  `tws` gains the TRCO ADDRESS here -- the OC.query that
           follows the k-loop -- so unlike 13/14 this is not t2_good riding
           through.  It needs the LEFT disjunct, get_typeidx = trcotype. *)
        rewrite -cats1 all_cat /=.
        split; 1: by move: n16; rewrite /t2_good; smt().
        have hadz : R_TRH_Gproc.ad{2} = adz by smt().
        rewrite hadz.
        by left; apply trcoaddr_gettype; smt(size_ge0).
      + by rewrite hszts.
      + by smt().
      + by smt().
      + by rewrite n20.
      by smt().
    (* L'-LOOP ENTRY+EXIT.  MM45 FORS_ES.ec:5751-5790.  pre = 17, exit = 20
       (measured).  Both sides are in the LONGHAND form here -- the outer and
       l'-loop invariants are the two that predate the op layer -- so the folds
       are applied through STEP 18's bridges. *)
    wp; skip => &1 &2 [#]
                          x01 x02 x03 x04 x05 x06 x07 x08 x09 x10 x11 x12 
                          x13 x14 x15 x16 x17.
    (* ENTRY: skFORSl and pkFORSl start [], so the B-level disjunct and the
       B-level nth characterisation are both vacuous. *)
    split.
    + rewrite /=; do! split => //.
      - move=> adx; rewrite x08; split; first by move=> h; left.
        case=> [// | [j u v w] [[hj0 hj1] _]].
        by have := ler_lt_trans _ _ _ hj0 hj1; rewrite ltrr.
      - move=> j u v w [hj0 hj1].
        by have := ler_lt_trans _ _ _ hj0 hj1; rewrite ltrr.
      by apply (ler_trans 2) => //; exact ge2_lp.
    move=> pkL skL twsR tsR pkR skR gL gR [#]
           y01 y02 y03 y04 y05 y06 y07 y08 y09 y10 y11 y12 y13 y14 y15 y16 
           y17 y18 y19 y20.
    (* EXIT: the guard plus the invariant pin size skR = l' exactly. *)
    have hl : size skR = l' by smt().
    have hmem : forall (adx : adrs * dgst),
        adx \in tsR <=> t2_memA tsR (size R_TRH_Gproc.skFORSs{2} + 1) adx.
    + move=> adx; have h := y10 adx; rewrite hl in h.
      rewrite (t2_memA_fold tsR (size R_TRH_Gproc.skFORSs{2}) adx _);
        1: smt(size_ge0).
      smt(t2_memA_raw t2_memB_raw).
    have hnthA : t2_nthA tsR R_TRH_Gproc.ad{2} pp{2}
        (rcons R_TRH_Gproc.skFORSs{2} skR) (size R_TRH_Gproc.skFORSs{2} + 1).
    + apply (t2_nthA_fold tsR R_TRH_Gproc.ad{2} pp{2} R_TRH_Gproc.skFORSs{2}
               skR (size R_TRH_Gproc.skFORSs{2})).
      - done.
      - by rewrite t2_nthA_raw; exact y11.
      (* NOT `-hl` in the goal: l' also occurs inside t2_off's expansion, so a
         global rewrite moves that too.  Same trap as `-hk` at the k-exit. *)
      have h12 := y12; rewrite hl in h12.
      by rewrite t2_nthB_raw; exact h12.
    have hszts : size tsR
        = (size R_TRH_Gproc.skFORSs{2} + 1) * l' * k * (2 ^ a - 1).
    + have h := y16; rewrite hl in h.
      by rewrite -t2_size_fold_l0; exact h.
    split; last by smt(size_rcons).
    rewrite ?size_rcons.
    do ! split.
    + by smt().
    + by smt().
    + by smt().
    + by smt().
    + by smt().
    + by smt().
    + by smt().
    + by move=> adx; rewrite -t2_memA_raw; exact (hmem adx).
    + by move: hnthA;
         rewrite /t2_nthA /t2_entry_sk /t2_entry_lvs /t2_pre /t2_off
                 /t2_span /t2_adT.
    + by smt().
    + by smt().
    + by smt().
    + by rewrite hszts.
    + by smt().
    by smt().
  (* T2 OUTER ENTRY+EXIT.  MM45 FORS_ES.ec:5791-5860, and the same shape as
     T3's: `wp; rnd; wp; skip` (NOT `wp; skip` -- both sides sample), the entry
     is vacuous at i < 0, and the exit hands the seq post its nth-ts
     characterisation from the loop's. *)
  inline{2} 3; inline{2} 2.
  wp; rnd; wp; skip => />.
  move=> psL _.
  split; 1: smt(expr_gt0).
  move=> pkfs skfs tws ts /lezNgt ges_szskfs _ tsdef nthts uqunz1ts allts
         alltws szts eqszskpkfs les_szskfs.
  split => [i j u v w * |]; 1: by rewrite nthts /#.
  smt().
(* T2-SUFFIX: MM45 FORS_ES.ec:5861-5943.  CLOSED 2026-08-07 (this was the last
   admit in the file, and the only one that was not loop plumbing -- it is the
   reduction's mathematical core).  The notes below are kept as the record of
   how it was scoped and what was established before it was attempted:

   SHAPE (read off a goal dump).  The right side has 21 statements; (17)-(21)
   are the oracle calls -- O_SMDTTCR_Default.get / nr_targets / dist_tweaks /
   get_tweaks and O_THFC_Default.get_tweaks -- so they inline first.  T3's
   analogous suffix (_t3.ec:1229) is the template: inline the oracle calls, then
   `wp N M => /=`, THEN `conseq (: _ ==> .. collision statement ..)`.

   THE CONSEQ MUST COME AFTER THE WP.  Applied first, nrts/dist/twsO/twsOC are
   still universally quantified with nothing tying them to ts/tws, and the
   subgoal is unprovable.  (T3 records this; it cost a cycle there.)

   TWO FLAGS, NOT ONE.  Kimi flagged this specifically for T2 and it is the
   difference from T3: the conseq premise must retain BOTH
   `EUF_CMA_Gproc_V.valid_TRHTCR{1}` (POSITIVE -- this is the TRH branch) AND
   `! EUF_CMA_Gproc_V.valid_OpenPRE{1}`.  In T3 the single load-bearing flag was
   `! valid_TRHTCR`; dropping either one here leaves the final goal unclosable.

   ALSO NEEDED: a `size ts <= t_smdttcr` bound for SM_DT_TCR_C, analogous to
   T3's nrtrees_lp_l, derived from this file's size conjunct
   `size ts = nr_trees 0 * l' * k * t2_span`.  MM45 cite `dval`; we have no such
   lemma and T3 had to prove its own.

   IT IS A PORT.  MM45's argument (~85 lines) runs through
   extract_collision_bt_ap_trh, list2tree_fullybalanced / list2tree_height /
   list2tree_lvb, and bs2int/int2bs index manipulation over `g (mco mk m)`.  I
   twice called this a re-derivation on the ground that C10 swaps that extractor
   for M.F.hC -- see the retraction at hC_is_g: hC IS `g (mco mk m)` by pure
   delta, so MM45's text transfers after unfolding it. *)
inline{2} 21; inline{2} 20; inline{2} 19; inline{2} 18; inline{2} 17.
wp 21 15 => /=.
conseq (: _
          ==>
             is_valid{1}
          /\ is_fresh{1}
          /\ ! EUF_CMA_Gproc_V.covered{1}
          /\ ! EUF_CMA_Gproc_V.valid_OpenPRE{1}
          /\ EUF_CMA_Gproc_V.valid_TRHTCR{1}
          =>
             0 <= cidx{2} < size FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2}
          /\ (nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2} cidx{2}).`2
             <> c{2}
          /\ trh pp{2}
                (nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2} cidx{2}).`1
                (nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2} cidx{2}).`2
             = trh pp{2}
                (nth witness FTWES.TRHC_TCR.O_SMDTTCR_Default.ts{2} cidx{2}).`1
                c{2}) => //.
(* PHRASED OVER cidx{2}/c{2}, NOT i{2}/x{2}/x'{2}/tw{2}.  `wp 21 15` has already
   substituted the latter, so a conseq naming them talks about their PRE-state
   values -- unconstrained -- and the premise's antecedent then shares no term
   with its conclusion.  T3's conseq does name i/x/x'/tw, and it works there
   because its wp leaves them live; copying that shape here produced a premise
   whose hypothesis and goal were about different things, and `smt` failing on
   `0 <= z12` was the symptom. *)
(* CONSEQ PREMISE.  Dumped and understood; five facts, each with its source:
     0 <= cidx < size ts          <- the conseq's own conclusion
     0 <= size ts <= l * k * (t-1) <- nrtrees_lp_l, below: the size conjunct
                                      gives nr_trees 0 * l' * k * (2^a - 1),
                                      and nr_trees 0 * l' = l makes that
                                      EXACTLY the SM_DT_TCR target bound
     uniq (unzip1 ts)             <- the invariant
     (nth ts cidx).`2 <> c  and the trh equation
                                  <- the conseq's x <> x' and trh x = trh x'
     disj_lists (unzip1 ts) tws   <- allts / alltws are disjoint predicates,
                                      the hasPn/allP argument T3 uses *)
- move=> /> &2 z01 z02 z03 z04 z05 z06 z07 z08 z09 z10 z11 z12 z13 z14 z15
               z16 z17 z18.
  have hc := z13 _; 1: by rewrite z14 z15 z16 z17 z18.
  do ! split.
  + smt().
  + smt().
  + smt(size_ge0).
  + by move=> _; rewrite z05 nrtrees_lp_l /t.
  + smt().
  + smt().
  rewrite hasPn => ad adints; rewrite -negP => adintws.
  move/allP: z03 => /(_ ad adints) /=.
  by move/allP: z04 => /(_ ad adintws) /=; smt(dist_adrstypes).
(* COLLISION CORE.  MM45 FORS_ES.ec:5798-5943.  CLOSED 2026-08-07 -- what
   follows was written while it was still the last admit.

   VERIFIED OPENING (0 errors, dumped):
     inline{1} 7; inline{1} 5.
     wp => /=.
   The left's two intermediate procedure calls -- pkFORS' at 5 and
   is_fresh <@ O_CMA_Gproc_I.fresh at 7 -- stop `wp` otherwise, which leaves
   `call` matching the wrong statements and `sim` raising an EqObsInError
   ANOMALY (not a normal failure, so it reads as a tool bug rather than a
   misalignment).  T3's identical incantation works because its left has no such
   calls in this window.

   CORRECTION.  I first recorded that our left has NO roots loop -- that GprocVI
   computes the root single-shot, so MM45's `while{1}` block does not apply.
   That is right about the TOP-LEVEL statements and wrong about the goal: once
   `pkFORS'` is inlined, its body contains exactly that loop, building `roots`
   by val_ap_trh (statement 10 after inlining, six sub-statements).  So MM45's
   while{1} step DOES apply; it was hidden behind the call.

   The while{1} invariant below is MM45's (FORS_ES.ec:5800-5822) with ONE
   simplification: they carry roots' and leaves' as two mkseqs, whereas our
   inlined loop computes the leaf inline, so a single mkseq suffices. *)
inline{1} 7; inline{1} 5.
wp => /=.
while{1} (   roots{1}
             = mkseq (fun (i : int) =>
                 FTWES.val_ap_trh ps0{1} ad0{1}
                   (nth witness (FTWES.DBAPKL.val sig{1}) i).`2
                   (bs2int (rev (take a (drop (a * i)
                      (FTWES.BLKAL.val m0{1})))))
                   (f ps0{1} (set_thtbidx ad0{1} 0
                      (i * t + bs2int (rev (take a (drop (a * i)
                         (FTWES.BLKAL.val m0{1}))))))
                      (DigestBlock.val
                         (nth witness (FTWES.DBAPKL.val sig{1}) i).`1))
                   i)
               (size roots{1})
          /\ 0 <= size roots{1} <= k)
         (k - size roots{1}).
+ move=> _ z.
  wp; skip => /> &2 hrs hge0 hle hguard.
  by rewrite ?size_rcons mkseqS 1:size_ge0 /= -hrs /#.
wp => /=.
call (: ={glob O_CMA_Gproc_I}); 1: by sim.
skip => />.
(* DENSE ARGUMENT.  MM45 FORS_ES.ec:5836-5943 -- the forgery-to-collision step,
   and the last thing in this file.

   MEASURED (probe, 0 errors), so the next pass starts here rather than
   rediscovering it.  Intro arity is 8:
     move=> &2 w1 w2 w3 w4 w5 w6 w7 w8.
   with w1 = the raw nth-ts characterisation, w2 = uniq, w3 = allts,
   w4 = alltws, w5 = the size conjunct, w6 : msg * sigGproc = the forgery,
   w7 : msg list = the CMA query messages, w8 : (mkey * msg) list = the CMA
   oracle's transcript.

   T3's analogous argument (_t3.ec:1360-1420, CLOSED) transfers for the OPENING:
   pose vidx, the two range facts by divz_ge0/ltz_divLR and modz_ge0/ltz_pmod,
   `fit` as the find over the uncovered indices, `hasnin` from -has_predC,
   `szhc` from M.F.size_g, `rng_fit` from find_ge0 + -has_find, and eqfit1/eqfit2
   from hC_inst / hC_pos.  All of that is name-for-name.

   IT DIVERGES AT THE END, and that is the real remaining work: T3 concludes a
   TRCO collision -- ONE compression over the flattened root list, closed by
   eq_from_flatten_nth + neq_from_nth + DigestBlock.val_inj.  T2 must instead
   locate WHERE ON THE MERKLE PATH the collision sits, which is MM45's
   ecbtapP / extract_collision_bt_ap_trh block (5896 onwards) with its
   foldlupdhbidx and take_rev_int2bs index manipulation.  That block has no
   analogue in T3 and is the piece that has to be ported rather than copied. *)
(* OPENING, VERIFIED (compiles): the 8-hypothesis intro and the while ENTRY,
   which is `[] = mkseq _ 0` and closes by mkseq0 exactly as T3's does.
   Everything from here is the argument proper. *)
move=> &2 w1 w2 w3 w4 w5 w6 w7 w8.
split; 1: by rewrite mkseq0 /=; smt(ge1_k).
(* After `forall roots_L` the goal is a CONJUNCTION, not an implication: the
   while{1} rule emits its TERMINATION obligation (variant <= 0 => guard
   false) alongside the exit continuation.  An intro pattern that assumes an
   implication reports `nothing to introduce` at the SECOND name, which reads
   like a wrong arity rather than a wrong shape. *)
move=> rs; split; 1: by move=> _ _ _ hv; smt().
(* NOTE the last name: `ntcr` holds valid_TRHTCR POSITIVE (root' = root) -- it
   is NOT a negated flag.  The name is T3's, where the branch does use the
   negation, and both reviewers flagged it as misleading.  Kept for diff-ability
   against _t3.ec; the polarity is asserted here so the name cannot mislead. *)
move=> /lezNgt gek_szrs hrs hge0 hle hpredC eq_out ninqs ncov nopre ntcr.
(* T3's opening, transferred name-for-name (_t3.ec:1360-1400).  w6 is the
   forgery, so w6.`1 = m' and w6.`2.`1 = mk'; w8 is the CMA transcript. *)
pose vidx := Index.val (FTWES.mco w6.`2.`1 w6.`1).`2.
have rngi : 0 <= vidx %/ l' < nr_trees 0.
+ by rewrite divz_ge0 2:ltz_divLR; smt(ge2_lp nrtrees_lp_l Index.valP).
have rngj : 0 <= vidx %% l' < l'.
+ by rewrite modz_ge0 2:ltz_pmod; 1,2: smt(ge2_lp).
have szrs : size rs = k by smt().
pose fit := List.find
  (fun (idxs : int * int * int) =>
     ! (idxs \in
        flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2) w8)))
  (M.F.hC w6.`2.`1 w6.`1).
have hasnin :
  has
    (fun (idxs : int * int * int) =>
       ! (idxs \in
          flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2) w8)))
    (M.F.hC w6.`2.`1 w6.`1).
+ by move: ncov; rewrite -has_predC.
have szhc : size (M.F.hC w6.`2.`1 w6.`1) = k.
+ by rewrite /M.F.hC M.F.size_g.
have rng_fit : 0 <= fit < k.
+ rewrite /fit find_ge0 /= -szhc.
  by rewrite -has_find hasnin.
have eqfit1 : (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`1 = vidx.
+ by rewrite /vidx; exact (hC_inst w6.`2.`1 w6.`1 fit rng_fit).
have eqfit2 : (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`2 = fit.
+ by exact (hC_pos w6.`2.`1 w6.`1 fit rng_fit).
move/nth_find: (hasnin) => /= /(_ witness) /= nthgnin.
(* eqfit2 collapses (nth (M.F.hC ..) fit).`2 to `fit` throughout, which shrinks
   every term below substantially -- do it before anything else. *)
rewrite eqfit2.
(* REMAINING: MM45 FORS_ES.ec:5838-5943, the extraction.  The mapping is now
   established from a dump, so this is transcription, not discovery:

   The goal ALREADY contains FTWES.extract_collision_bt_ap_trh applied to
     1  pp{2}
     2  adT   = set_kpidx (set_tidx (set_typeidx adz trhftype) (vidx %/ l'))
                          (vidx %% l')
     3  l2bt  = list2tree (mkseq (fun i => f pp{2} (set_thtbidx adT 0
                          (fit * t + i)) (val (nth (nth (DBLLKTL.val skF) fit) i))) t)
     4  apv   = FTWES.DBAL.val (nth (FTWES.DBAPKL.val w6.`2.`2) fit).`2
     5  bits  = rev (int2bs a (nth (M.F.hC w6.`2.`1 w6.`1) fit).`3)
     6  lf'   = the forged leaf, f pp{2} (set_thtbidx adT 0 ..) ..
     7  lf    = the honest leaf
     8  (a, fit)
   which is exactly MM45's argument list at 5839-5846, with their cmidx -> our
   FTWES.mco w6.`2.`1 w6.`1, l -> l', trhtype -> trhftype, g (..) -> M.F.hC.

   OVERCLAIM RETRACTED (adversarial review, GPT-5.6, 2026-08-07).  This block
   previously said the mapping was established and the rest was "transcription,
   not discovery".  That is too strong, and the reviewer is right: the
   definitions appear aligned and no contradiction has been found, but the
   OMITTED MM45 BLOCK IS WHERE THE ALIGNMENT IS ACTUALLY PROVED.  Until it
   closes, the reduction is not shown to win, and describing what is left as
   transcription understates it.

   So the next step is their three invocations, ON THOSE SAME TERMS:
     move: (ecbtapP      (trhi pp{2} adT) updhbidx l2bt apv bits lf' lf (a, fit)).
     move: (ecbtap_vals  (trhi pp{2} adT) updhbidx l2bt apv bits lf' lf (a, fit)).
     move: (ecbtabp_props(trhi pp{2} adT) updhbidx l2bt apv bits lf' lf (a, fit)).
   then their case analysis on the returned tuple (5896 onwards).

   OUR FLAGS ARE THE MIRROR OF T3's, and this is where they enter: `nopre`
   (! valid_OpenPRE) gives lf' <> lf, and `tcr` -- POSITIVE here, since this is
   the TRH branch -- gives root' = root.  Same root, different leaf, hence a
   collision somewhere on the path: that is precisely what the extraction
   locates. *)
pose adT := set_kpidx (set_tidx (set_typeidx adz trhftype) (vidx %/ l'))
                      (vidx %% l').
pose skF := nth witness (nth witness R_TRH_Gproc.skFORSs{2} (vidx %/ l'))
                        (vidx %% l').
pose bits := rev (int2bs a (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3).
pose apv := FTWES.DBAL.val
              (nth witness (FTWES.DBAPKL.val w6.`2.`2) fit).`2.
pose l2bt := list2tree (mkseq _ t).
pose lfp := f pp{2} (set_thtbidx adT 0
                       (fit * t + (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3))
                    (DigestBlock.val
                       (nth witness (unzip1 (FTWES.DBAPKL.val w6.`2.`2)) fit)).
pose lfh := f pp{2} (set_thtbidx adT 0
                       (fit * t + (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3))
                    (DigestBlock.val
                       (nth witness (nth witness (FTWES.DBLLKTL.val skF) fit)
                          (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3)).
move: (ecbtapP (FTWES.trhi pp{2} adT) FTWES.updhbidx l2bt apv bits lfp lfh
                (a, fit)).
rewrite /l2bt (list2tree_fullybalanced _ a) 3:/=; 1: smt(ge1_a).
+ by rewrite size_mkseq lez_maxr /t 1:expr_ge0.
rewrite /apv /bits FTWES.DBAL.valP size_rev size_int2bs lez_maxr /=;
  1: smt(ge1_a).
rewrite (list2tree_height _ a) 2:size_mkseq 2:// 2:lez_maxr 2:expr_ge0
                                2,3:// /=; 1: smt(ge1_a).
(* REMAINING PREMISES of ecbtapP: leaf <> leaf', the val_bt = val_ap equation,
   and vallf_subbt.  These are the three that consume our FLAGS, unlike the
   three above which were pure structure -- and that is where the work is.

   MEASURED about the first of them: `nopre` is phrased over
     (nth (M.F.hC ..) (find ..)).`1 %/ l'
   NOT over vidx.  eqfit1 equates the two but they are not syntactically equal,
   so smt cannot bridge it unaided.  T3's normalisation
     move: nopre; rewrite -/fit eqfit1 eqfit2 -/vidx => hnopre.
   applies cleanly, but the result still does not match lfp <> lfh by smt --
   so the leaf terms need normalising too, which is MM45's
     rewrite /lf'; move: (neqlfs); rewrite eqfit_gcm2 nth_mkseq ..
     rewrite /g /chunk /= nth_mkseq .. (nth_map witness) .. eq_sym => -> /=
   block at FORS_ES.ec:5878-5881.  That block is the next thing to port; it is
   the one place so far where MM45's line does NOT transfer as-is, because our
   honest leaf comes from the posed mkseq rather than from their `lf`.

   NOTE also: smt(h) where h is a HYPOTHESIS fails with "cannot find lemma" --
   smt takes lemma names and reads hypotheses from the context automatically. *)
(* The extractor's RANGE fact, needed by every nth_mkseq side condition
   below: nth_mkseq wants 0 <= idx < t, and that is M.F.rng_g -- an AXIOM about
   the index extractor -- not arithmetic.  hC_is_g is what lets mem_nth supply
   its membership premise. *)
have rngidx : 0 <= (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3 < t.
+ apply (M.F.rng_g (FTWES.mco w6.`2.`1 w6.`1)).
  by rewrite -hC_is_g mem_nth szhc; smt().
(* The DIFF, measured rather than guessed: hnopre and lfp/lfh are the SAME
   terms.  What stops smt is purely form --
     tree address   hnopre expanded   vs  posed adT
     secret key     hnopre expanded   vs  posed skF
     forged sk elt  (nth L fit).`1    vs  nth (unzip1 L) fit
     honest leaf    nth (cube ..) idx vs  explicit f ..
   so it needs two FOLDS plus nth_map and cube_is_mkseq/nth_mkseq. *)
move: nopre; rewrite -/fit eqfit1 eqfit2 -/vidx -/adT -/skF => hnopre.
rewrite cube_is_mkseq nth_mkseq 1:/# /= in hnopre.
have szsig : size (FTWES.DBAPKL.val w6.`2.`2) = k
  by smt(FTWES.DBAPKL.valP).
have hne : lfp <> lfh.
+ by rewrite /lfp /lfh (nth_map witness) 1:/#; exact hnopre.
rewrite hne /=.
(* Premise 5 is ntcr with the sides SWAPPED: val_ap_trh / val_bt_trh unfold
   (via their _gen forms) to exactly val_ap / val_bt at (a, fit).  Same folds as
   the leaf premise, plus cube_is_mkseq for the tree and nth_map for the forged
   sk element. *)
move: ntcr; rewrite -/fit eqfit1 eqfit2 -/vidx -/adT -/skF.
rewrite /FTWES.val_ap_trh /FTWES.val_ap_trh_gen /FTWES.val_bt_trh
        /FTWES.val_bt_trh_gen cube_is_mkseq => htcr.
have heq : val_bt (FTWES.trhi pp{2} adT) FTWES.updhbidx l2bt (a, fit)
         = val_ap (FTWES.trhi pp{2} adT) FTWES.updhbidx apv bits lfp (a, fit).
+ rewrite /l2bt /apv /bits /lfp (nth_map witness) 1:/#.
  by rewrite eq_sym; exact htcr.
rewrite heq /=.
(* Premise 6.  list2tree_lvb applies directly with s = mkseq _ t and e = a;
   its three side conditions are 0 <= a, size s = 2^a (size_mkseq plus t = 2^a),
   and 0 <= idx < size s, which is rngidx.  Then onth_nth + nth_mkseq turn
   `onth s idx` into lfh. *)
rewrite /l2bt /bits (list2tree_lvb _ _ a).
+ smt(ge1_a).
+ by rewrite size_mkseq lez_maxr /t 1:expr_ge0.
+ by rewrite size_mkseq lez_maxr /t 1:expr_ge0; smt().
rewrite (onth_nth witness) 1:size_mkseq 1:lez_maxr 1:expr_ge0 1:/#.
exact rngidx.
(* REMAINING: ecbtap_vals and ecbtabp_props on the SAME eight terms, then
   MM45's case analysis on the returned tuple (FORS_ES.ec:5896-5943).

   ATTEMPTED, and what was learned:

   * All three lemmas take the SAME six premises, so they should be hoisted
     into named `have`s once rather than discharged three times.  Four of the
     six are already inline above (fully_balanced, the size and height
     equations, vallf_subbt); hne and heq are already named.

   * Premises CANNOT be passed positionally after the (a, fit) argument:
     EasyCrypt parses them as formulas and rejects with "expecting a
     proof-term, not a formula".  Supply them by rewriting the premises away
     instead, as the ecbtapP block above does.

   * A `have hlvb : ..` whose proof itself uses `+` bullets left hlvb OUT of
     scope at the next tactic ("unknown lemma hlvb"), so the bullet nesting
     needs care -- that is what stopped this attempt, not the mathematics.

   * NOTE the vallf_subbt discharge ends `exact rngidx.`: after the
     list2tree_lvb / onth_nth chain the equality is already closed and only the
     index-range side condition survives.  Adding a further nth_mkseq there
     reports "nothing to rewrite", which reads like a missing step and is the
     opposite. *)
(* ecbtap_vals and ecbtabp_props take the SAME six premises.  Discharged by
   REPEATING the inline sequence rather than hoisting them into named `have`s:
   a `have` whose proof uses `+` bullets left its name out of scope at the next
   tactic.  Repetition is duplicative but it is the form already proved to work
   here, and hne / heq / rngidx are reused rather than re-derived. *)
move: (ecbtap_vals (FTWES.trhi pp{2} adT) FTWES.updhbidx l2bt apv bits lfp lfh
                    (a, fit)).
rewrite /l2bt (list2tree_fullybalanced _ a) 3:/=; 1: smt(ge1_a).
+ by rewrite size_mkseq lez_maxr /t 1:expr_ge0.
rewrite /apv /bits FTWES.DBAL.valP size_rev size_int2bs lez_maxr /=;
  1: smt(ge1_a).
rewrite (list2tree_height _ a) 2:size_mkseq 2:// 2:lez_maxr 2:expr_ge0
                                2,3:// /=; 1: smt(ge1_a).
rewrite hne /=.
rewrite heq /=.
rewrite /l2bt /bits (list2tree_lvb _ _ a).
+ smt(ge1_a).
+ by rewrite size_mkseq lez_maxr /t 1:expr_ge0.
+ by rewrite size_mkseq lez_maxr /t 1:expr_ge0; smt().
rewrite (onth_nth witness) 1:size_mkseq 1:lez_maxr 1:expr_ge0 1:/#.
exact rngidx.
move: (ecbtabp_props (FTWES.trhi pp{2} adT) FTWES.updhbidx l2bt apv bits lfp
                      lfh (a, fit)).
rewrite /l2bt (list2tree_fullybalanced _ a) 3:/=; 1: smt(ge1_a).
+ by rewrite size_mkseq lez_maxr /t 1:expr_ge0.
rewrite /apv /bits FTWES.DBAL.valP size_rev size_int2bs lez_maxr /=;
  1: smt(ge1_a).
rewrite (list2tree_height _ a) 2:size_mkseq 2:// 2:lez_maxr 2:expr_ge0
                                2,3:// /=; 1: smt(ge1_a).
rewrite hne /=.
rewrite heq /=.
rewrite /l2bt /bits (list2tree_lvb _ _ a).
+ smt(ge1_a).
+ by rewrite size_mkseq lez_maxr /t 1:expr_ge0.
+ by rewrite size_mkseq lez_maxr /t 1:expr_ge0; smt().
rewrite (onth_nth witness) 1:size_mkseq 1:lez_maxr 1:expr_ge0 1:/#.
exact rngidx.
(* Two residual premises survive the third discharge: apv unfolded against
   itself, and the vallf_subbt equality still wrapped in Some.  Close both, then
   destructure the extraction tuple as MM45 do at FORS_ES.ec:5896. *)
rewrite /apv /= nth_mkseq 1:/# /=.
(* Unfold the SPECIALISED extractor first.  Without this the goal keeps
   FTWES.extract_collision_bt_ap_trh while the pose/case act on the generic
   extract_collision_bt_ap, so the case analysis silently does not reach the
   goal at all -- it destructures a copy.  MM45 do the same unfold at
   FORS_ES.ec:5894. *)
rewrite /FTWES.extract_collision_bt_ap_trh.
pose ecbt := extract_collision_bt_ap _ _ _ _ _ _ _.
case: ecbt => /= [x1 x1' x2 x2' hbidx l r bs].
(* Each of the three conclusions arrives guarded by `f .. = lfh`, a residue of
   the vallf_subbt discharge -- and that equality is just lfh's own definition.
   Supply it once and apply all three. *)
have hlfh : f pp{2} (set_thtbidx adT 0
                       (fit * t + (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3))
                    (DigestBlock.val
                       (nth witness (nth witness (FTWES.DBLLKTL.val skF) fit)
                          (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3))
            = lfh by rewrite /lfh.
move=> /(_ hlfh) hprops /(_ hlfh) hvals /(_ hlfh) hP.
(* The winning index is t2_off at coordinates
     (vidx %/ l', vidx %% l', fit, hbidx.`1 - 1, hbidx.`2 %% nr_nodesf hbidx.`1)
   -- read off the goal, and matching t2_off's layout with v + 1 = hbidx.`1.
   w1 (the raw nth-ts characterisation) instantiated there is what identifies
   nth ts cidx with the address/children pair; GPT-5.6 flagged w1 as not yet
   consumed, and this is where it is consumed. *)
have hnth := w1 (vidx %/ l') (vidx %% l') fit (hbidx.`1 - 1)
                (hbidx.`2 %% nr_nodesf hbidx.`1).
(* ecbtap_vals has EIGHT conjuncts, not four: besides x1/x1'/x2/x2' it pins
   ct', l, r and bs'.  ct' is where hbidx's value lives -- hbidx is opaque after
   the case, so its height component has to come from here. *)
move: hvals => [#] hx1 hx1p hx2 hx2p hct hl hr hbs.
(* side condition hoisted: `1:smt(..)` does not parse inside a rewrite chain *)
have hrng : 0 <= a - size bs - 1 <= a by smt(ge1_a size_ge0).
have hh1 : hbidx.`1 = size bs + 1.
+ rewrite hct (FTWES.take_rev_int2bs a (a - size bs - 1)) 1:// 
          FTWES.foldlupdhbidx size_int2bs lez_maxr /=; smt(ge1_a).
(* Specialise the ts characterisation at the winning coordinates.  Ranges:
   rngi / rngj / rng_fit give the first three; hh1 turns the layer into size bs,
   whose bound is hprops' `size bs < a`; and the breadth is a %% so its range is
   modz_ge0 / ltz_pmod. *)
have hnthv := hnth _ _ _ _ _;
  1..5: smt(ge1_a ge1_k ge2_lp size_ge0 expr_gt0).
(* THE LAST MILE.  Everything is now connected; what remains is index
   arithmetic, MM45 FORS_ES.ec:5916-5943.

   hnthv gives the target entry as
     (set_thtbidx adT (v+1) (fit * nr_nodesf (v+1) + w),
      val (val_bt_trh_gen pp adT (oget (sub_bt l2bt path_false)) (v+1) ..)
      ++ val (val_bt_trh_gen pp adT (oget (sub_bt l2bt path_true )) (v+1) ..))
   with v = hbidx.`1 - 1 (= size bs, by hh1) and w = hbidx.`2 %% nr_nodesf hbidx.`1.

   hvals gives x1 = val_bt (trhi pp adT) updhbidx l (updhbidx hbidx false) and
   x1' likewise on r, with hl / hr pinning l and r as the two sub_bt children at
   the SAME path.  val_bt_trh_gen ps ad bt h i IS val_bt (trhi ps ad) updhbidx
   bt (h, i) by definition, so the two sides are the same term once the index
   pair matches -- that is the whole remaining obligation:

     updhbidx hbidx false / true  vs  (v+1, fit * nr_nodesf (v+1) + w)

   Then conjunct 2 and conjunct 3 both fall straight out of hP, which already
   states (x1, x1') <> (x2, x2') and trh ct' x1 x1' = trh ct' x2 x2'.

   ATTEMPTED, and the crux is isolated.  The index match reduces to ONE fact:

     hbidx.`2 %/ nr_nodesf hbidx.`1 = fit

   i.e. the breadth index PACKS (tree, position).  It follows from hct: with
   n = a - size bs - 1, take_rev_int2bs + foldlupdhbidx give
     hbidx = (a - n, fit * 2^n + bs2int (int2bs n X)),   X = idx %/ 2^(a-n)
   and hnn : nr_nodesf hbidx.`1 = 2^n, so divzMDl leaves
     fit + bs2int (int2bs n X) %/ 2^n = fit
   which needs bs2int (int2bs n X) = X (int2bsK, given 0 <= X < 2^n from
   rngidx) and then X %/ 2^n = 0.

   Both `hnn` and the positivity fact compile; what does NOT close is that last
   division, even with int2bsK / pdiv_small / bs2int_le2Xs as smt hints.  It
   needs int2bsK applied EXPLICITLY with its range side-condition discharged,
   not handed to smt as a hint -- smt will not chain the round-trip through the
   size_int2bs max.

   Deliberately not called 'transcription' -- per the retraction above, this
   index matching IS where the alignment is proved. *)
(* THE PACKING FACT.  int2bsK applied EXPLICITLY, with its range side-condition
   discharged as its own `have` -- handing it to smt as a hint does not work,
   because smt will not chain the round-trip through size_int2bs's max. *)
have hgt : 0 < 2 ^ (a - size bs - 1) by smt(expr_gt0).
have hnn : nr_nodesf hbidx.`1 = 2 ^ (a - size bs - 1).
+ by rewrite hh1 /nr_nodesf; congr; smt().
have hXrng :
  0 <= (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3 %/ 2 ^ (size bs + 1)
     < 2 ^ (a - size bs - 1).
+ split => [| _]; 1: by rewrite divz_ge0; smt(expr_gt0).
  rewrite ltz_divLR 1:expr_gt0 1://.
  have -> : 2 ^ (a - size bs - 1) * 2 ^ (size bs + 1) = 2 ^ a.
  - by rewrite -exprD_nneg; smt(ge1_a size_ge0).
  smt().
have hbs2 :
  bs2int (int2bs (a - size bs - 1)
            ((nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3 %/ 2 ^ (size bs + 1)))
  = (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3 %/ 2 ^ (size bs + 1).
+ by apply int2bsK; smt(size_ge0 ge1_a).
have hh2 : hbidx.`2 %/ nr_nodesf hbidx.`1 = fit.
+ rewrite hnn hct (FTWES.take_rev_int2bs a (a - size bs - 1)) 1://
          FTWES.foldlupdhbidx /= size_int2bs lez_maxr 1:/#.
  rewrite (: a - (a - size bs - 1) = size bs + 1) 1:/# hbs2.
  by rewrite divzMDl 1://; smt(pdiv_small).
(* Normalise hnthv so its address is exactly trhi's: the layer index needs
   hbidx.`1 - 1 + 1 = hbidx.`1, and the breadth needs the PACKING fact, since
   fit * nr_nodesf hbidx.`1 + hbidx.`2 %% nr_nodesf hbidx.`1 IS hbidx.`2 by
   divz_eq once hh2 gives the quotient. *)
have heq1 : hbidx.`1 - 1 + 1 = hbidx.`1 by smt().
have hpack : fit * nr_nodesf hbidx.`1 + hbidx.`2 %% nr_nodesf hbidx.`1
           = hbidx.`2.
+ by rewrite -hh2; smt(divz_eq).
move: hnthv; rewrite heq1 hpack => hnthv2.
rewrite hnthv2 /=.
(* WHAT IS LEFT, after hnthv2 is rewritten in: three conjuncts, and only the
   last two have content.

   Conjunct 1 is the index range -- arithmetic over bigi_nnf_ge0 / expr_ge0 and
   the size conjunct.

   Conjuncts 2 and 3 need ONE identity: the goal's children are
     val_bt_trh_gen pp adT (oget (sub_bt l2bt (rev (int2bs (a - v) (2w)))))
                    v (fit * nr_nodesf v + 2w)                 [and 2w+1]
   while hvals gives x1 / x1' as val_bt over l / r at updhbidx hbidx false/true,
   with hl / hr pinning l and r as sub_bt children at rcons (take ..) false/true.
   val_bt_trh_gen ps ad bt h i IS val_bt (trhi ps ad) updhbidx bt (h, i), so
   what must be shown is that the two INDEX PAIRS and the two PATHS coincide:

     index:  fit * nr_nodesf (hbidx.`1 - 1) + 2w  =  2 * hbidx.`2
             -- follows from hpack plus nr_nodesf (v) = 2 * nr_nodesf (v+1);
     path:   rev (int2bs (a - v) (2w))  =  rcons (take (..) bs) false
             -- the bit-list identity, and the part with real content.

   Then conjunct 2 is hP's (x1,x1') <> (x2,x2') and conjunct 3 is hP's
   trh equality, since trhi ps ad hbidx x x' unfolds to
   trh ps (set_thtbidx ad hbidx.`1 hbidx.`2) (val x ++ val x') and hnthv2's
   address is exactly that after hpack.

   ATTEMPTED: nr_nodesf (hbidx.`1 - 1) = 2 * nr_nodesf hbidx.`1 does not fall to
   `rewrite /nr_nodesf hh1; smt(exprS ..)`; the exponent arithmetic
   (a - (size bs + 1 - 1) vs a - (size bs + 1)) needs to be normalised by hand
   first.  That is the next concrete step, and it is small. *)
(* Exponent arithmetic normalised by hand first, then exprS.  The obstacle was
   that a - (hbidx.`1 - 1) and (a - hbidx.`1) + 1 are equal but not syntactically
   so, and exprS only matches the second. *)
have hnn2 : nr_nodesf (hbidx.`1 - 1) = 2 * nr_nodesf hbidx.`1.
+ rewrite /nr_nodesf.
  have -> : a - (hbidx.`1 - 1) = (a - hbidx.`1) + 1 by smt().
  by rewrite exprS 1:/#.
(* MM45's FINAL BLOCK, FORS_ES.ec:5921-5943, with the name mapping.  It is
   ~25 lines of index manipulation -- their densest -- and the shape is:

     pose vb := val_bt_trh_gen _ _ _ _ _; pose vb' := val_bt_trh_gen _ _ _ _ _.
     suff: x1 = vb /\ x1' = vb'.
     - move=> -[<- <-]; rewrite .. => -> /=.
       move: eqout => @/trhi.                      <- ours: hP's second conjunct
       rewrite hbidxval ... (pmod_small (bs2int _)) ...
       move=> -> /=; rewrite eqseq_cat 1:2!valP 1://; move: neqin; ...
       by move: neqxor (val_inj x1 x2) (val_inj x1' x2') => + /contra + /contra /#.
     rewrite x1val /vb x1pval /vb' hbidxval /val_bt_trh_gen lval rval ...
     split; do 3! congr; rewrite (int2bs_cat 1 (a - size bs)) 1:/#
                                 (int2bs_cons 1) 1://.
     - ... int2bs0s ... expr1 mulKz ... -rev_cons ... bs2intK
     ... dvdzE (mulrC 2) modzMDl ... divzMDl ... bs2intK

   NAME MAPPING into this file:
     nthts   -> hnthv2      hbidxval -> hct        lval / rval -> hl / hr
     x1val   -> hx1         x1pval   -> hx1p       neqin / eqout -> hP's two
     eqfit_gcm2 -> eqfit2   nr_nodes -> nr_nodesf  rtd -> bits

   The two child identities are where the content is: each reduces, via
   int2bs_cat / int2bs_cons at position 1, to the fact that
   int2bs (n+1) (2X) = false :: int2bs n X (and the `true`/2X+1 mirror), which
   is exactly the parent/child bit-path relation.  hnn2 above supplies the
   accompanying nr_nodesf halving.

   It was NOT a small step (though the pose/suff scaffold turned out to be the
   wrong shape -- see the closing block below).  Everything it consumes is
   proved and in scope (hnthv2, hct, hl, hr, hx1, hx1p, hP,
   hpack, hh1, hh2, hnn, hnn2, rngidx, szsig). *)
(* CLOSING SCRIPT from adversarial review (GPT-5.6), verified citation by
   citation before use.  Two things in it I had not seen: the upper bound is
   MY OWN t2_off_mono_i instantiated at the top coordinate (nr_trees 0,0,0,0,0)
   -- I had been trying to redo that arithmetic by hand -- and the path identity
   is FTWES.rcons_take_rev_int2bs, which states exactly
   rcons (take j (rev (int2bs i n))) b = rev (int2bs (j+1) (2*(n %/ 2^(i-j)) + b)).
   Both checked against base-c10-split before applying. *)
split.
- split.
  + have hi0 : 0 <= vidx %/ l' by move: rngi => [#].
    have hj0 : 0 <= vidx %% l' by move: rngj => [#].
    have hf0 : 0 <= fit by move: rng_fit => [#].
    have hl0 : 0 <= l'.
    * apply (ler_trans 2); [trivial | exact ge2_lp].
    have hk0 : 0 <= k.
    * apply (ler_trans 1); [trivial | exact ge1_k].
    have hspan0 : 0 <= 2 ^ a - 1
      by rewrite ler_subr_addl /= -(ltzE 0 (2 ^ a)) expr_gt0.
    have hnrpos : 0 < nr_nodesf hbidx.`1 by rewrite hnn expr_gt0.
    have hmod0 : 0 <= hbidx.`2 %% nr_nodesf hbidx.`1
      by rewrite modz_ge0 1:neq_ltz hnrpos.
    have hsum0 := bigi_nnf_ge0 1 hbidx.`1.
    rewrite ?addr_ge0 ?mulr_ge0; 1..9: assumption.
    exact hsum0.
    exact hmod0.
  + move=> _.
    have hbslt : size bs < a by move: hprops => [#].
    have hv : 0 <= hbidx.`1 - 1 < a.
    * rewrite hh1 /=.
      split.
      - exact (size_ge0 bs).
      move=> _; exact hbslt.
    have hw : 0 <= hbidx.`2 %% nr_nodesf hbidx.`1
                < nr_nodesf ((hbidx.`1 - 1) + 1).
    * rewrite heq1 hnn.
      split.
      - by rewrite modz_ge0 neq_ltz expr_gt0.
      - move=> _; by rewrite ltz_pmod expr_gt0.
    have hzj : 0 <= 0 < l'.
    * split; 1: trivial.
      move=> _; apply (ltr_le_trans 2); [trivial | exact ge2_lp].
    have hzu : 0 <= 0 < k.
    * split; 1: trivial.
      move=> _; apply (ltr_le_trans 1); [trivial | exact ge1_k].
    have hzv : 0 <= 0 < a.
    * split; 1: trivial.
      move=> _; apply (ltr_le_trans 1); [trivial | exact ge1_a].
    have hzw : 0 <= 0 by trivial.
    have hoff :=
      t2_off_mono_i
        (vidx %/ l') (vidx %% l') fit
        (hbidx.`1 - 1) (hbidx.`2 %% nr_nodesf hbidx.`1)
        (nr_trees 0) 0 0 0 0
        rngi rngj rng_fit hv hw hzj hzu hzv hzw.
    have hcur :
      vidx %/ l' * l' * k * (2 ^ a - 1)
        + vidx %% l' * k * (2 ^ a - 1)
        + fit * (2 ^ a - 1)
        + bigi predT nr_nodesf 1 hbidx.`1
        + hbidx.`2 %% nr_nodesf hbidx.`1
      = t2_off (vidx %/ l') (vidx %% l') fit
          (hbidx.`1 - 1) (hbidx.`2 %% nr_nodesf hbidx.`1).
    * by rewrite /t2_off /t2_span heq1.
    have htop :
      t2_off (nr_trees 0) 0 0 0 0 = nr_trees 0 * l' * k * (2 ^ a - 1).
    * by rewrite /t2_off /t2_span big_geq.
    by rewrite w5 hcur -htop; exact hoff.
- have hn0 : 0 <= a - size bs - 1.
  + by move: hrng => [hn0 _]; exact hn0.
  have hden : a - (a - size bs - 1) = size bs + 1 by ring.
  have hrem :
    hbidx.`2 %% nr_nodesf hbidx.`1 =
      (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3 %/ 2 ^ (size bs + 1).
  + rewrite hnn hct (FTWES.take_rev_int2bs a (a - size bs - 1)) 1:hrng.
    rewrite hden FTWES.foldlupdhbidx /= size_int2bs lez_maxr 1:hn0 hbs2.
    by rewrite modzMDl
         (pmod_small
            ((nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3 %/
               2 ^ (size bs + 1))) 1:hXrng.
  have hlen : a - (hbidx.`1 - 1) = a - size bs by rewrite hh1; ring.
  have hn1 : a - size bs - 1 + 1 = a - size bs by ring.
  have hpath0 :
    rev (int2bs (a - (hbidx.`1 - 1))
           (2 * (hbidx.`2 %% nr_nodesf hbidx.`1)))
    = rcons (take (a - size bs - 1)
               (rev (int2bs a (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3)))
            false.
  + rewrite (FTWES.rcons_take_rev_int2bs a (a - size bs - 1)
               (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3 false) 1:hrng /=.
    by rewrite hrem hlen hden hn1.
  have hpath1 :
    rev (int2bs (a - (hbidx.`1 - 1))
           (2 * (hbidx.`2 %% nr_nodesf hbidx.`1) + 1))
    = rcons (take (a - size bs - 1)
               (rev (int2bs a (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3)))
            true.
  + rewrite (FTWES.rcons_take_rev_int2bs a (a - size bs - 1)
               (nth witness (M.F.hC w6.`2.`1 w6.`1) fit).`3 true) 1:hrng /=.
    by rewrite hrem hlen hden hn1.
  (* `rewrite -hpack; ring` LOOKS like it proves this and does not: -hpack
     rewrites hbidx.`2 EVERYWHERE, including the copy inside
     `hbidx.`2 %% nr_nodesf hbidx.`1`, so ring is left with
     `-2 * w + 2 * ((fit * nnf + w) %% nnf) = 0` -- true, but not a ring
     identity.  That residue sat as a second pending goal and was being
     absorbed by the trailing `admit.`, i.e. the identity was NOT proved while
     the file reported it as one more closed step.  Only the goal dump showed
     it.  Directing the rewrite at the RHS occurrence alone fixes it. *)
  have hidx0 :
    fit * nr_nodesf (hbidx.`1 - 1) + 2 * (hbidx.`2 %% nr_nodesf hbidx.`1)
    = 2 * hbidx.`2.
  + have -> : 2 * hbidx.`2
              = 2 * (fit * nr_nodesf hbidx.`1 + hbidx.`2 %% nr_nodesf hbidx.`1)
      by rewrite hpack.
    by rewrite hnn2; ring.
  (* THE FINAL BLOCK.  MM45 writes it as
     `pose vb := val_bt_trh_gen _ _ _ _ _; suff: x1 = vb /\ x1' = vb'`, but that
     pose reports "cannot find an occurence" HERE, because the goal's children
     are not in that syntactic form until the val_bt_trh_gen / updhbidx deltas
     are taken -- the pattern search runs before the unfolding it needs.
     Kimi K3's fix (adversarial review, 2026-08-07) is to drop the pose and
     state each child equation OUTRIGHT, transcribed from the goal, so the
     match holds by construction instead of by search.  Everything the two
     equations consume is proved above: hpath0 / hpath1 (the bit paths, from
     FTWES.rcons_take_rev_int2bs), hidx0 (the breadth index, from hnn2+hpack),
     cube_is_mkseq (leaf tree), and /adT + /skF to expand the two pose-locals
     so both sides are literally the same term. *)
  have -> :
    FTWES.val_bt_trh_gen pp{2}
      (set_kpidx (set_tidx (set_typeidx adz trhftype) (vidx %/ l')) (vidx %% l'))
      (oget
         (sub_bt
            (list2tree
               (fors_leaves_op_cube
                  (nth witness
                     (nth witness R_TRH_Gproc.skFORSs{2} (vidx %/ l'))
                     (vidx %% l')) pp{2}
                  (set_kpidx (set_tidx (set_typeidx adz trhftype) (vidx %/ l'))
                     (vidx %% l')) fit))
            (rev
               (int2bs (a - (hbidx.`1 - 1))
                  (2 * (hbidx.`2 %% nr_nodesf hbidx.`1))))))
      (hbidx.`1 - 1)
      (fit * nr_nodesf (hbidx.`1 - 1) + 2 * (hbidx.`2 %% nr_nodesf hbidx.`1))
    = x1.
  + rewrite hx1 hl /FTWES.val_bt_trh_gen /FTWES.updhbidx /= /adT /skF.
    by rewrite cube_is_mkseq hpath0 hidx0.
  have -> :
    FTWES.val_bt_trh_gen pp{2}
      (set_kpidx (set_tidx (set_typeidx adz trhftype) (vidx %/ l')) (vidx %% l'))
      (oget
         (sub_bt
            (list2tree
               (fors_leaves_op_cube
                  (nth witness
                     (nth witness R_TRH_Gproc.skFORSs{2} (vidx %/ l'))
                     (vidx %% l')) pp{2}
                  (set_kpidx (set_tidx (set_typeidx adz trhftype) (vidx %/ l'))
                     (vidx %% l')) fit))
            (rev
               (int2bs (a - (hbidx.`1 - 1))
                  (2 * (hbidx.`2 %% nr_nodesf hbidx.`1) + 1)))))
      (hbidx.`1 - 1)
      (fit * nr_nodesf (hbidx.`1 - 1) + 2 * (hbidx.`2 %% nr_nodesf hbidx.`1) + 1)
    = x1'.
  + rewrite hx1p hr /FTWES.val_bt_trh_gen /FTWES.updhbidx /= /adT /skF.
    by rewrite cube_is_mkseq hpath1 hidx0.
  move: hP => [hPne hPeq].
  split.
  + (* `<>` here is BOOLEAN negation, not an implication, so `move=> hcat`
       has nothing to introduce.  Split the concatenation with eqseq_cat and
       hand smt the two injectivity facts as HYPOTHESES -- val_inj is stated
       as `injective val`, and in that form it does not fire as an smt hint. *)
    have hi1 := DigestBlock.val_inj x1 x2.
    have hi2 := DigestBlock.val_inj x1' x2'.
    have hsz : size (DigestBlock.val x1) = size (DigestBlock.val x2)
      by rewrite 2!DigestBlock.valP.
    by rewrite (eqseq_cat _ _ _ _ hsz); smt().
  + by move: hPeq; rewrite /FTWES.trhi /adT => ->.
qed.

(* The V<->VI hop for T2's EVENT.  GprocVI.ec's certified gproc_V_VI_eq is
   stated only for T3's event (! valid_TRHTCR); its underlying byequiv already
   proves ={res, covered, valid_OpenPRE, valid_TRHTCR}, so the same proof gives
   this one.  Replayed HERE rather than added to GprocVI.ec because that file is
   certified and a new lemma there moves the split census -- a deliberate
   re-baseline, not a drive-by.  Promote both together when T2 lands. *)
lemma gproc_V_VI_eq_trh
  (A <: Adv_EUFCMA_Gproc{-O_CMA_Gproc_I, -EUF_CMA_Gproc_I, -EUF_CMA_Gproc_V}) &m :
    Pr[EUF_CMA_Gproc_V(A).main() @ &m :
         ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
         /\ EUF_CMA_Gproc_V.valid_TRHTCR]
  = Pr[EUF_CMA_Gproc_VI(A).main() @ &m :
         ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
         /\ EUF_CMA_Gproc_V.valid_TRHTCR].
proof.
byequiv (_ : ={glob A} ==>
             ={res}
          /\ EUF_CMA_Gproc_V.covered{1}       = EUF_CMA_Gproc_V.covered{2}
          /\ EUF_CMA_Gproc_V.valid_OpenPRE{1} = EUF_CMA_Gproc_V.valid_OpenPRE{2}
          /\ EUF_CMA_Gproc_V.valid_TRHTCR{1}  = EUF_CMA_Gproc_V.valid_TRHTCR{2}) => //.
proc.
seq 3 3 : (={glob A, ps, ad, pkFORSnt, skFORSnt}).
+ by call gprockg_vi_eq; auto.
sim.
qed.

lemma t2_trh_bound
  (A <: Adv_EUFCMA_Gproc{-O_CMA_Gproc_I, -EUF_CMA_Gproc_I, -EUF_CMA_Gproc_V,
                         -R_TRH_Gproc,
                         -FTWES.TRHC_TCR.O_SMDTTCR_Default,
                         -FTWES.TRHC.O_THFC_Default}) &m :
    Pr[EUF_CMA_Gproc_V(A).main() @ &m :
         ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
         /\ EUF_CMA_Gproc_V.valid_TRHTCR]
  <= Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(A),
           FTWES.TRHC_TCR.O_SMDTTCR_Default, FTWES.TRHC.O_THFC_Default).main() @ &m : res].
proof. by rewrite (gproc_V_VI_eq_trh A &m); apply (t2_trh_bound_VI A &m). qed.
