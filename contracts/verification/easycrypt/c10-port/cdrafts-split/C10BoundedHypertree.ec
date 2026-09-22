(* Bounded NPRF hypertree signing. A failed layer returns no signature;
   the remaining layer slots perform no cryptographic work. This uses the
   existing sampled-key model and is not a Rust extraction. *)
require import AllCore List Distr IntDiv BinaryTrees MerkleTrees.
require import C10BoundedSigning XmssmtCC_All.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme C10BoundedGrind XMSSMT_C_Scheme.

module BoundedHypertree = {
  proc leaves_from_sklpsad = FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad
  proc sign(sk : skWOTS list list list * pseed * adrs, m : msgFLSLXMSSMTTW, idx : index) : sigFLSLXMSSMTTWC option = {
    var i : int;
    var bad : bool;
    var result : (sigWOTS * cntr) option;
    var ps : pseed;
    var ad : adrs;
    var tidx, kpidx : int;
    var skWOTS : skWOTS;
    var sigWOTS : sigWOTS;
    var counter : cntr;
    var skWOTSlp : skWOTS list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var ap : apFLXMSSTW;
    var sapl : sigFLSLXMSSMTTWC;
    var root : dgstblock;

    (skWOTStd, ps, ad) <- sk;

    i <- 0; bad <- false;
    root <- m;
    sapl <- [];
    (tidx, kpidx) <- (Index.val idx, 0);
    while (i < d) {
      if (!bad) {
        (tidx, kpidx) <- edivz tidx l';

        (* Extract the WOTS+C secret key from the cube: layer (size sapl), inner
           tree (tidx), key pair (kpidx). *)
        skWOTSlp <- nth witness (nth witness skWOTStd (size sapl)) tidx;
        skWOTS <- nth witness skWOTSlp kpidx;

        (* Only successful bounded WOTS output enters a hypertree signature. *)
        result <@ BoundedSign.sign((skWOTS, ps, set_kpidx (set_typeidx (set_ltidx ad (size sapl) tidx) chtype) kpidx), root);

        if (result = None) { bad <- true; } else {
          (sigWOTS, counter) <- oget result;
          leaves <@ leaves_from_sklpsad(skWOTSlp, ps, (set_ltidx ad (size sapl) tidx));
          ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhxtype) (list2tree leaves) kpidx;
          root <- val_bt_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhxtype) (list2tree leaves);

          sapl <- rcons sapl ((sigWOTS, counter), ap);
        }
      }
      i <- i + 1;
    }

    return if bad then None else Some sapl;
  }
}.

lemma total_bounded_wots_sign :
  equiv[WOTS_C_ES.sign ~ BoundedSign.sign :
    ={sk, m} ==> res{2} <> None => res{2} = Some res{1}].
proof.
  proc*; inline{2} BoundedSign.sign.
  sp 0 2.
  seq 0 1 : (sk{1} = sk0{2} /\ m{1} = m0{2}).
  + by call{2} search_ll; auto.
  sp 0 1; if{2}.
  + wp; call (_ : ={arg} ==> ={res}); first by sim.
    by auto.
  by wp; call{1} WOTS_C_ES_sign_ll; auto.
qed.

lemma bounded_hypertree_sign_ll : islossless BoundedHypertree.sign.
proof.
  proc; while true (d - i).
  + move=> z; wp; if.
    - seq 4 : (d - i = z).
      + call (_ : true ==> true); first by conseq bounded_sign_ll.
        by auto; smt().
      + by call bounded_sign_ll; auto.
      if; first by auto; smt().
      + by wp; call leaves_sklpsad_ll; auto; smt().
      hoare; call (_ : true ==> true); first by conseq bounded_sign_ll.
      + by auto.
      by auto.
    by auto; smt().
  by auto; smt().
qed.

lemma bounded_hypertree_sign_size :
  hoare[BoundedHypertree.sign : true ==> res <> None => size (oget res) = d].
proof.
  proc; while (0 <= i <= d /\ (!bad => size sapl = i)).
  + wp; if.
    - seq 4 : (0 <= i < d /\ !bad /\ size sapl = i).
      + call (_ : true ==> true); first by conseq bounded_sign_ll.
        by auto; smt().
      if; first by auto; smt().
      by wp; call leaves_sklpsad_h; auto; smt(size_rcons).
    by auto; smt().
  by auto; smt(ge1_d).
qed.

lemma total_bounded_hypertree_sign :
  equiv[FL_SL_XMSS_MT_C_ES_NPRF.sign ~ BoundedHypertree.sign :
    ={sk, m, idx} ==> res{2} <> None => res{2} = Some res{1}].
proof.
  proc.
  while (={skWOTStd, ps, ad} /\ i{2} = size sapl{1} /\
    (!bad{2} => ={root, sapl, tidx, kpidx})).
  + wp; if{2}.
    - seq 4 4 : (={skWOTStd, ps, ad} /\ i{2} = size sapl{1} /\
        !bad{2} /\ ={root, sapl, tidx, kpidx, skWOTSlp} /\
        (result{2} <> None => result{2} = Some (sigWOTS{1}, counter{1}))).
      + by call total_bounded_wots_sign; auto; smt().
      if{2}.
      + wp; call{1} leaves_sklpsad_ll; auto; smt(size_rcons).
      wp; call (_ : ={arg} ==> ={res}); first by sim.
      auto; smt(size_rcons).
    wp; call{1} leaves_sklpsad_ll; call{1} WOTS_C_ES_sign_ll.
    auto; smt(size_rcons).
  by auto; smt().
qed.

module BoundedHypertreeGame
  (A : Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF, OC : FSSLXMTWES.TRHC.Oracle_THFC) = {
  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pk : pkFLSLXMSSMTTW;
    var sk : skWOTS list list list * pseed * adrs;
    var ml : msgFLSLXMSSMTTW list;
    var sigl : sigFLSLXMSSMTTWC list;
    var m, m' : msgFLSLXMSSMTTW;
    var result : sigFLSLXMSSMTTWC option;
    var sig' : sigFLSLXMSSMTTWC;
    var idx' : index;
    var i : int;
    var bad, win, is_valid : bool;

    ad <- adz;
    ps <$ dpseed;
    OC.init(ps);
    ml <@ A(OC).choose();
    (pk, sk) <@ FL_SL_XMSS_MT_C_ES_NPRF.keygen(ps, ad);
    sigl <- []; i <- 0; bad <- false;
    while (i < l) {
      if (!bad) {
        m <- nth witness ml i;
        result <@ BoundedHypertree.sign(sk, m, Index.insubd i);
        if (result = None) { bad <- true; }
        else { sigl <- rcons sigl (oget result); }
      }
      i <- i + 1;
    }
    win <- false;
    if (!bad) {
      (m', sig', idx') <@ A(OC).forge(pk, sigl);
      is_valid <@ FL_SL_XMSS_MT_C_ES_NPRF.verify(pk, m', sig', idx');
      win <- is_valid /\ m' <> nth witness ml (Index.val idx');
    }
    return win;
  }
}.

lemma hypertree_verify_ll : islossless FL_SL_XMSS_MT_C_ES_NPRF.verify.
proof.
  proc; inline *; wp; while true (d - i).
  + move=> z; wp; while true (len - size pkWOTS_l).
    - by auto; smt(size_rcons).
    by auto; smt().
  by auto; smt().
qed.

(* The same nonadaptive adversary and collection oracle are coupled. Only
   forge needs an explicit termination premise: the bounded game omits it
   after a failed search. Shared choose/keygen calls are coupled directly. *)
lemma total_bounded_hypertree_main
  (A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF {-FC.O_THFC_Default}) :
  islossless A(FC.O_THFC_Default).forge =>
  equiv[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A, FC.O_THFC_Default).main ~
        BoundedHypertreeGame(A, FC.O_THFC_Default).main :
    ={glob A} ==> res{2} => res{1}].
proof.
  move=> A_forge_ll; proc.
  seq 6 8 : (={pk, sk, ml, glob A, glob FC.O_THFC_Default} /\
    i{2} = size sigl{1} /\ (!bad{2} => ={sigl})).
  + wp; call (_ : ={arg} ==> ={res}); first by sim.
    call (_ : ={glob FC.O_THFC_Default}); first by sim.
    inline *; by auto.
  seq 1 1 : (={pk, sk, ml, glob A, glob FC.O_THFC_Default} /\
    i{2} = size sigl{1} /\ (!bad{2} => ={sigl})).
  + while (={pk, sk, ml, glob A, glob FC.O_THFC_Default} /\
      i{2} = size sigl{1} /\ (!bad{2} => ={sigl})).
    - wp; if{2}.
      + seq 2 2 : (={pk, sk, ml, glob A, glob FC.O_THFC_Default} /\
          i{2} = size sigl{1} /\ !bad{2} /\ ={sigl} /\
          (result{2} <> None => result{2} = Some sig{1})).
        * by call total_bounded_hypertree_sign; auto; smt().
        by if{2}; auto; smt(size_rcons).
      by wp; call{1} nprf_sign_ll; auto; smt(size_rcons).
    by auto; smt().
  sp 0 1; if{2}.
  + wp; call (_ : ={arg} ==> ={res}); first by sim.
    call (_ : true); by auto; smt().
  by wp; call{1} hypertree_verify_ll; call{1} A_forge_ll; auto.
qed.

lemma bounded_hypertree_win_le_total
  (A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF {-FC.O_THFC_Default}) &m :
  islossless A(FC.O_THFC_Default).forge =>
  Pr[BoundedHypertreeGame(A, FC.O_THFC_Default).main() @ &m : res] <=
  Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A, FC.O_THFC_Default).main() @ &m : res].
proof.
  move=> A_forge_ll.
  byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
  symmetry; conseq (total_bounded_hypertree_main A A_forge_ll); smt().
qed.

lemma bounded_wots_miss :
  hoare[BoundedSign.sign : !prefix_hit sk.`2 sk.`3 m ==> res = None].
proof.
  proc*; exists* sk, m; elim* => sk0 m0.
  by call (bounded_sign_failure sk0 m0); auto; smt().
qed.

(* Concrete first-layer exhaustion cannot release even a partial signature. *)
lemma bounded_hypertree_first_failure :
  hoare[BoundedHypertree.sign :
    !prefix_hit sk.`2
      (set_kpidx (set_typeidx
        (set_ltidx sk.`3 0 (Index.val idx %/ l')) chtype) (Index.val idx %% l')) m
    ==> res = None].
proof.
  proc; unroll 7.
  while bad.
  + rcondf 1; by auto.
  rcondt 7; first by auto; smt(ge1_d).
  rcondt 7; first by auto.
  seq 10 : (result = None).
  + by call bounded_wots_miss; auto; smt().
  by rcondt 1; auto; smt().
qed.
