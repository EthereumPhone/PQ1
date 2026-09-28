(* Functional correctness of WOTS signing/recovery and constructed Merkle paths. *)
require import AllCore List Distr C10BoundedSigning XMSSMT_C_Scheme BinaryTrees MerkleTrees BitEncoding.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES WOTS_C_Real WOTS_C_Scheme EmsgWOTS BS2Int.

(* Functional specifications of the actual NPRF WOTS+C procedures. *)

op public_key (sk : skWOTS) (ps : pseed) (ad : adrs) : pkWOTS =
  DBLL.insubd (mkseq (fun i => cf ps (set_chidx ad i) 0 (w-1)
    (DigestBlock.val (nth witness (DBLL.val sk) i))) len).

op signature (sk : skWOTS) (ps : pseed) (ad : adrs) (em : emsgWOTS) : sigWOTS =
  DBLL.insubd (mkseq (fun i => cf ps (set_chidx ad i) 0 (BaseW.val em.[i])
    (DigestBlock.val (nth witness (DBLL.val sk) i))) len).

op recovered_key (sig : sigWOTS) (ps : pseed) (ad : adrs) (em : emsgWOTS) : pkWOTS =
  DBLL.insubd (mkseq (fun i => cf ps (set_chidx ad i) (BaseW.val em.[i])
    (w-1-BaseW.val em.[i]) (DigestBlock.val (nth witness (DBLL.val sig) i))) len).

lemma recover_signature sk ps ad em : valid_wadrs ad =>
  recovered_key (signature sk ps ad em) ps ad em = public_key sk ps ad.
proof.
  move=> ha; rewrite /recovered_key /signature /public_key DBLL.insubdK.
  + by rewrite size_mkseq; smt(ge2_len).
  congr; apply eq_in_mkseq => i hi.
  rewrite /= nth_mkseq 1:hi /=.
  have hv : valid_wadrs (set_chidx ad i).
  + apply validwadrs_setchidx; first exact ha.
    by rewrite /valid_chidx.
  rewrite eq_sym /cf
    {1}(_ : w-1 = BaseW.val em.[i] + (w-1-BaseW.val em.[i])) 1:/#.
  by rewrite ch_comp 1:hv //=; smt(BaseW.valP DigestBlock.valP).
qed.

lemma public_key_spec sk0 ps0 ad0 :
  hoare[WOTS_TW_ES_NPRF.pkWOTS_from_skWOTS :
    skWOTS = sk0 /\ ps = ps0 /\ ad = ad0 ==> res = public_key sk0 ps0 ad0].
proof.
  proc; while (skWOTS = sk0 /\ ps = ps0 /\ ad = ad0 /\
    pkWOTS = mkseq (fun i => cf ps0 (set_chidx ad0 i) 0 (w-1)
      (DigestBlock.val (nth witness (DBLL.val sk0) i))) (size pkWOTS) /\
    size pkWOTS <= len).
  + by auto => />; smt(size_rcons mkseqS size_ge0).
  by auto => />; rewrite /public_key; smt(ge2_len mkseq0).
qed.

lemma signature_spec sk0 m0 :
  hoare[WOTS_C_ES.sign : sk = sk0 /\ m = m0 ==>
    res = (signature sk0.`1 sk0.`2 sk0.`3
      (encode_msgWOTS_C sk0.`2 sk0.`3 m0 (grindC sk0.`2 sk0.`3 m0)),
      grindC sk0.`2 sk0.`3 m0)].
proof.
  proc; while (skWOTS = sk0.`1 /\ ps = sk0.`2 /\ ad = sk0.`3 /\
    counter = grindC sk0.`2 sk0.`3 m0 /\
    em = encode_msgWOTS_C sk0.`2 sk0.`3 m0 counter /\
    sig = mkseq (fun i => cf ps (set_chidx ad i) 0 (BaseW.val em.[i])
      (DigestBlock.val (nth witness (DBLL.val skWOTS) i))) (size sig) /\
    size sig <= len).
  + by auto => />; smt(size_rcons mkseqS size_ge0).
  by auto => />; rewrite /signature; smt(ge2_len mkseq0).
qed.

lemma recovered_key_spec m0 sig0 cc0 ps0 ad0 :
  hoare[XMSSMT_C_Scheme.FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C :
    m = m0 /\ sigWOTS = sig0 /\ counter = cc0 /\ ps = ps0 /\ ad = ad0 ==>
    res = (recovered_key sig0 ps0 ad0 (encode_msgWOTS_C ps0 ad0 m0 cc0),
      predC (ThC ps0 ad0 m0 cc0))].
proof.
  proc; wp; while (m = m0 /\ sigWOTS = sig0 /\ counter = cc0 /\ ps = ps0 /\ ad = ad0 /\
    em = encode_msgWOTS_C ps0 ad0 m0 cc0 /\
    pkWOTS_l = mkseq (fun i => cf ps0 (set_chidx ad0 i) (BaseW.val em.[i])
      (w-1-BaseW.val em.[i]) (DigestBlock.val (nth witness (DBLL.val sig0) i)))
      (size pkWOTS_l) /\ size pkWOTS_l <= len).
  + by auto => />; smt(size_rcons mkseqS size_ge0).
  by auto => />; rewrite /recovered_key; smt(ge2_len mkseq0).
qed.

lemma bounded_signature_spec (sk0 : skWOTS * pseed * adrs) (m0 : dgstblock) :
  hoare[BoundedSign.sign : sk = sk0 /\ m = m0 ==>
    res <> None =>
    oget res = (signature sk0.`1 sk0.`2 sk0.`3
      (encode_msgWOTS_C sk0.`2 sk0.`3 m0 (grindC sk0.`2 sk0.`3 m0)),
      grindC sk0.`2 sk0.`3 m0) /\
    predC (ThC sk0.`2 sk0.`3 m0 (oget res).`2)].
proof.
  proc; seq 1 : (sk = sk0 /\ m = m0 /\ search_result sk0.`2 sk0.`3 m0 r).
  + by call (search_contract sk0.`2 sk0.`3 m0); auto.
  sp 1; if.
  + wp; call (signature_spec sk0 m0); auto => />.
    rewrite /search_result /hit; smt().
  by auto.
qed.

lemma bounded_recovery_spec (sk0 : skWOTS * pseed * adrs) (m0 : dgstblock) :
  valid_wadrs sk0.`3 =>
  hoare[BoundedSign.sign : sk = sk0 /\ m = m0 ==>
    res <> None =>
    recovered_key (oget res).`1 sk0.`2 sk0.`3
      (encode_msgWOTS_C sk0.`2 sk0.`3 m0 (oget res).`2) =
      public_key sk0.`1 sk0.`2 sk0.`3 /\
    predC (ThC sk0.`2 sk0.`3 m0 (oget res).`2)].
proof.
  move=> ha; conseq (bounded_signature_spec sk0 m0) => // />.
  smt(recover_signature).
qed.

lemma constructed_path_correct (ps : pseed) (ad : adrs) (leaves : dgstblock list) (idx : int) :
  size leaves = l' => 0 <= idx < l' =>
  val_ap_trh ps ad (cons_ap_trh ps ad (list2tree leaves) idx) idx (nth witness leaves idx) =
  val_bt_trh ps ad (list2tree leaves).
proof.
  move=> hs hi.
  have hp : 0 <= h' by smt(ge1_hp).
  have [#] ht hb hl := list2tree_ok leaves h' hp hs.
  have hbs : size (rev (int2bs h' idx)) = h' by rewrite size_rev size_int2bs; smt(ge1_hp).
  have hap : size (cons_ap (trhi ps ad) updhbidx (list2tree leaves)
    (rev (int2bs h' idx)) (h',0)) = h'.
  + by rewrite size_consap // ht hbs.
  rewrite /val_ap_trh /cons_ap_trh /cons_ap_trh_gen DBHPL.insubdK 1:/#
    /val_ap_trh_gen /val_bt_trh eq_sym.
  apply eq_valbt_valap => //.
  + by rewrite hap.
  + by rewrite hap hbs.
  + rewrite hl 1:/#; smt(onth_nth).
  move=> i hi'; apply nth_consap => //; smt().
qed.
