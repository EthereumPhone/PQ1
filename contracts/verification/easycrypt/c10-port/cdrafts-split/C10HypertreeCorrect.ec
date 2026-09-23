(* Accepted bounded signatures satisfy a public path predicate. Transparent observation carries that predicate into the total game. *)
require import AllCore List Distr IntDiv BinaryTrees MerkleTrees C10WOTSCorrect C10BoundedHypertree C10HypertreeCoverage XmssmtCC_All.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.

op leaf (sk : skWOTS) (ps : pseed) (ad : adrs) (u : int) =
  pkco ps (set_kpidx (set_typeidx ad pkcotype) u)
    (flatten (map DigestBlock.val (DBLL.val (public_key sk ps
      (set_kpidx (set_typeidx ad chtype) u))))).

op leaves (sks : skWOTS list) (ps : pseed) (ad : adrs) =
  mkseq (fun u => leaf (nth witness sks u) ps ad u) l'.

lemma leaves_size sks ps ad : size (leaves sks ps ad) = l'.
proof. rewrite /leaves size_mkseq; smt(ge2_lp). qed.

lemma leaves_nth sks ps ad u : 0 <= u < l' =>
  nth witness (leaves sks ps ad) u = leaf (nth witness sks u) ps ad u.
proof. by move=> hu; rewrite /leaves nth_mkseq. qed.

lemma leaves_spec sks0 ps0 ad0 :
  hoare[FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad :
    skWOTSl = sks0 /\ ps = ps0 /\ ad = ad0 ==> res = leaves sks0 ps0 ad0].
proof.
  proc; while (skWOTSl = sks0 /\ ps = ps0 /\ ad = ad0 /\
    leaves = mkseq (fun u => leaf (nth witness sks0 u) ps0 ad0 u) (size leaves) /\
    size leaves <= l').
  + wp; exists* leaves; elim* => prefix.
    call (public_key_spec (nth witness sks0 (size prefix)) ps0
      (set_kpidx (set_typeidx ad0 chtype) (size prefix))).
    auto => />; rewrite /leaf; smt(size_rcons mkseqS size_ge0).
  by auto => />; rewrite /leaves; smt(ge2_lp mkseq0).
qed.

type path_state = int * dgstblock * bool * int.


op path_step (ps : pseed) (ad : adrs) (st : path_state)
  (sap : (sigWOTS * cntr) * apFLXMSSTW) : path_state =
  let tk = edivz st.`1 l' in
  let wad = ht_chad ad st.`4 tk.`1 tk.`2 in
  let em = encode_msgWOTS_C ps wad st.`2 sap.`1.`2 in
  let pk = recovered_key sap.`1.`1 ps wad em in
  let lf = pkco ps (set_kpidx (set_typeidx (set_ltidx ad st.`4 tk.`1) pkcotype) tk.`2)
    (flatten (map DigestBlock.val (DBLL.val pk))) in
  (tk.`1, val_ap_trh ps (set_typeidx (set_ltidx ad st.`4 tk.`1) trhxtype)
    sap.`2 tk.`2 lf, st.`3 /\ predC (ThC ps wad st.`2 sap.`1.`2), st.`4+1).

op path_result (ps : pseed) (ad : adrs) (m : dgstblock) (idx : int)
  (sig : sigFLSLXMSSMTTWC) : path_state =
  foldl (path_step ps ad) (idx,m,true,0) sig.

lemma signed_step_correct ps ad tidx m good layer sks (sigc : sigWOTS * cntr) :
  valid_wadrs (ht_chad ad layer (tidx %/ l') (tidx %% l')) =>
  recovered_key sigc.`1 ps (ht_chad ad layer (tidx %/ l') (tidx %% l'))
    (encode_msgWOTS_C ps (ht_chad ad layer (tidx %/ l') (tidx %% l')) m sigc.`2) =
    public_key (nth witness sks (tidx %% l')) ps
      (ht_chad ad layer (tidx %/ l') (tidx %% l')) =>
  path_step ps ad (tidx,m,good,layer)
    (sigc, cons_ap_trh ps (set_typeidx (set_ltidx ad layer (tidx %/ l')) trhxtype)
      (list2tree (leaves sks ps (set_ltidx ad layer (tidx %/ l')))) (tidx %% l')) =
  (tidx %/ l',
   val_bt_trh ps (set_typeidx (set_ltidx ad layer (tidx %/ l')) trhxtype)
     (list2tree (leaves sks ps (set_ltidx ad layer (tidx %/ l')))),
   good /\ predC (ThC ps (ht_chad ad layer (tidx %/ l') (tidx %% l')) m sigc.`2),
   layer+1).
proof.
  move=> hv hp.
  have hu : 0 <= tidx %% l' < l' by smt(modz_ge0 ltz_pmod ge2_lp).
  rewrite /path_step /= hp.
  rewrite -/(leaf (nth witness sks (tidx %% l')) ps
    (set_ltidx ad layer (tidx %/ l')) (tidx %% l')).
  rewrite -(leaves_nth sks ps (set_ltidx ad layer (tidx %/ l')) (tidx %% l') hu).
  by rewrite constructed_path_correct 1:leaves_size.
qed.

op remaining_idx (idx layer : int) =
  if layer = 0 then idx else if layer = 1 then idx %/ l' else 0.

lemma remaining_step idx layer :
  0 <= idx < l => 0 <= layer < d =>
  remaining_idx idx layer %/ l' = remaining_idx idx (layer+1).
proof.
  rewrite d_val ht_capacity /remaining_idx subtree_width => hi hl.
  have hc : layer = 0 \/ layer = 1 by smt().
  case: hc => -> /=; first by [].
  rewrite divz_small; smt(divz_ge0 ltz_divLR).
qed.

lemma remaining_valid idx layer ad :
  valid_xadrs ad => 0 <= idx < l => 0 <= layer < d =>
  valid_wadrs (ht_chad ad layer
    (remaining_idx idx layer %/ l') (remaining_idx idx layer %% l')).
proof.
  move=> ha hi hl; rewrite /ht_chad.
  apply validxadrs_validwadrs_setallboch => //.
  + rewrite /valid_tidx tree_count 1:hl /remaining_idx subtree_width.
    move: hi hl; rewrite ht_capacity d_val.
    case (layer = 0) => hc hi hl /=.
    - smt(divz_ge0 ltz_divLR).
    have h1 : layer = 1 by smt(); rewrite h1 /=.
    smt(divz_ge0 ltz_divLR).
  rewrite /valid_kpidx; smt(modz_ge0 ltz_pmod ge2_lp).
qed.

lemma bounded_path_correct (sk0 : skWOTS list list list * pseed * adrs)
  (m0 : dgstblock) (idx0 : index) :
  valid_xadrs sk0.`3 =>
  hoare[BoundedHypertree.sign : sk = sk0 /\ m = m0 /\ idx = idx0 ==>
    res <> None =>
    (path_result sk0.`2 sk0.`3 m0 (Index.val idx0) (oget res)).`3 /\
    size (oget res) = d].
proof.
  move=> ha.
  have hi : 0 <= Index.val idx0 < l by exact (Index.valP idx0).
  proc; while (
    skWOTStd = sk0.`1 /\ ps = sk0.`2 /\ ad = sk0.`3 /\
    0 <= i <= d /\
    (!bad => size sapl = i /\
      tidx = remaining_idx (Index.val idx0) i /\
      path_result ps ad m0 (Index.val idx0) sapl = (tidx,root,true,i))).
  + wp; if; last by auto; smt().
    exists* tidx, root, sapl, i; elim* => ti0 rt0 sa0 i0.
    seq 4 : (
      skWOTStd = sk0.`1 /\ ps = sk0.`2 /\ ad = sk0.`3 /\
      i = i0 /\ 0 <= i0 < d /\ !bad /\ sapl = sa0 /\ size sa0 = i0 /\
      ti0 = remaining_idx (Index.val idx0) i0 /\
      path_result ps ad m0 (Index.val idx0) sa0 = (ti0,rt0,true,i0) /\
      root = rt0 /\ tidx = ti0 %/ l' /\ kpidx = ti0 %% l' /\
      skWOTSlp = nth witness (nth witness sk0.`1 i0) (ti0 %/ l') /\
      (result <> None =>
        recovered_key (oget result).`1 ps (ht_chad ad i0 tidx kpidx)
          (encode_msgWOTS_C ps (ht_chad ad i0 tidx kpidx) rt0 (oget result).`2) =
          public_key (nth witness skWOTSlp kpidx) ps (ht_chad ad i0 tidx kpidx) /\
        predC (ThC ps (ht_chad ad i0 tidx kpidx) rt0 (oget result).`2))).
    - call (bounded_signature_spec
        (nth witness (nth witness (nth witness sk0.`1 i0) (ti0 %/ l')) (ti0 %% l'),
         sk0.`2, ht_chad sk0.`3 i0 (ti0 %/ l') (ti0 %% l')) rt0).
      auto => />; rewrite /ht_chad; smt(remaining_valid recover_signature).
    if; first by auto; smt().
    wp; call (leaves_spec (nth witness (nth witness sk0.`1 i0) (ti0 %/ l'))
      sk0.`2 (set_ltidx sk0.`3 i0 (ti0 %/ l'))).
    auto => /> &hr ge0 lt hb ht hs hn.
    have [hp hpred] := hs hn.
    rewrite size_rcons.
    split; first by smt().
    split; first by [].
    split; first by apply remaining_step; smt().
    rewrite /path_result in ht.
    rewrite /path_result foldl_rcons ht.
    have hv : valid_wadrs (ht_chad sk0.`3 (size sa0)
      (remaining_idx (Index.val idx0) (size sa0) %/ l')
      (remaining_idx (Index.val idx0) (size sa0) %% l'))
      by apply remaining_valid; smt().
    have he := signed_step_correct sk0.`2 sk0.`3
      (remaining_idx (Index.val idx0) (size sa0)) rt0 true (size sa0)
      (nth witness (nth witness sk0.`1 (size sa0))
        (remaining_idx (Index.val idx0) (size sa0) %/ l')) (oget result{hr}) hv hp.
    by rewrite he hpred.
  by auto => />; rewrite /path_result /remaining_idx /=; smt(ge1_d).
qed.

lemma keygen_layout ps0 ad0 :
  hoare[FL_SL_XMSS_MT_C_ES_NPRF.keygen : ps = ps0 /\ ad = ad0 ==>
    res.`1.`2 = ps0 /\ res.`1.`3 = ad0 /\ res.`2.`2 = ps0 /\ res.`2.`3 = ad0].
proof.
  proc; wp; call leaves_sklpsad_h.
  wp; while (ps = ps0 /\ ad = ad0).
  + wp; while (ps = ps0 /\ ad = ad0).
    - wp; while (ps = ps0 /\ ad = ad0).
      + wp; while (ps = ps0 /\ ad = ad0); by auto.
      by auto.
    by auto.
  by auto.
qed.

op good_transcript (pk : pkFLSLXMSSMTTW) (ml : msgFLSLXMSSMTTW list)
  (sigs : sigFLSLXMSSMTTWC list) =
  size sigs = l /\ forall j, 0 <= j < l =>
    size (nth witness sigs j) = d /\
    (path_result pk.`2 pk.`3 (nth witness ml j) j (nth witness sigs j)).`3.

module Observe (A : Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF, OC : TRHC.Oracle_THFC) = {
  var messages : msgFLSLXMSSMTTW list
  var signatures : sigFLSLXMSSMTTWC list
  var public : pkFLSLXMSSMTTW
  proc choose() : msgFLSLXMSSMTTW list = {
    messages <@ A(OC).choose();
    return messages;
  }
  proc forge(pk : pkFLSLXMSSMTTW, sigl : sigFLSLXMSSMTTWC list) :
    msgFLSLXMSSMTTW * sigFLSLXMSSMTTWC * index = {
    var answer;
    public <- pk; signatures <- sigl;
    answer <@ A(OC).forge(pk,sigl);
    return answer;
  }
}.

lemma bounded_path_input (sk0 : skWOTS list list list * pseed * adrs)
  (m0 : dgstblock) (idx0 : index) :
  hoare[BoundedHypertree.sign : sk = sk0 /\ m = m0 /\ idx = idx0 /\ valid_xadrs sk0.`3 ==>
    res <> None => (path_result sk0.`2 sk0.`3 m0 (Index.val idx0) (oget res)).`3 /\
    size (oget res) = d].
proof.
  case (valid_xadrs sk0.`3) => ha.
  + conseq (bounded_path_correct sk0 m0 idx0 ha); smt().
  by exfalso; smt().
qed.

lemma keygen_consistency :
  hoare[FL_SL_XMSS_MT_C_ES_NPRF.keygen : valid_xadrs ad ==>
    res.`1.`2 = res.`2.`2 /\ res.`1.`3 = res.`2.`3 /\ valid_xadrs res.`2.`3].
proof.
  proc*; exists* ps, ad; elim* => ps0 ad0.
  by call (keygen_layout ps0 ad0); auto; smt().
qed.

lemma bounded_transcript_good
  (A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF {-Observe,-FC.O_THFC_Default}) :
  hoare[BoundedHypertreeGame(Observe(A),FC.O_THFC_Default).main : true ==>
    res => good_transcript Observe.public Observe.messages Observe.signatures].
proof.
  proc; seq 5 : (pk.`2 = sk.`2 /\ pk.`3 = sk.`3 /\ valid_xadrs sk.`3 /\
    Observe.messages = ml).
  + call keygen_consistency.
    inline Observe(A,FC.O_THFC_Default).choose.
    wp; call (_ : true).
    - by proc; auto.
    inline *; auto; smt(valx_adz).
  seq 4 : (pk.`2 = sk.`2 /\ pk.`3 = sk.`3 /\ valid_xadrs sk.`3 /\
    Observe.messages = ml /\
    (!bad => size sigl = l /\ forall j, 0 <= j < l =>
      size (nth witness sigl j) = d /\
      (path_result pk.`2 pk.`3 (nth witness ml j) j (nth witness sigl j)).`3)).
  + while (pk.`2 = sk.`2 /\ pk.`3 = sk.`3 /\ valid_xadrs sk.`3 /\
      Observe.messages = ml /\ 0 <= i <= l /\
      (!bad => size sigl = i /\ forall j, 0 <= j < i =>
        size (nth witness sigl j) = d /\
        (path_result pk.`2 pk.`3 (nth witness ml j) j (nth witness sigl j)).`3)).
    - wp; if; last by auto; smt().
      seq 2 : (pk.`2 = sk.`2 /\ pk.`3 = sk.`3 /\ valid_xadrs sk.`3 /\
        Observe.messages = ml /\ 0 <= i < l /\ !bad /\ size sigl = i /\
        (forall j, 0 <= j < i => size (nth witness sigl j) = d /\
          (path_result pk.`2 pk.`3 (nth witness ml j) j (nth witness sigl j)).`3) /\
        (result <> None => size (oget result) = d /\
          (path_result pk.`2 pk.`3 (nth witness ml i) i (oget result)).`3)).
      + exists* sk, ml, i; elim* => sk0 ml0 i0.
        call (bounded_path_input sk0 (nth witness ml0 i0) (Index.insubd i0)).
        auto => />; smt(Index.insubdK).
      if; auto => />; smt(size_rcons nth_rcons).
    by auto => />; smt(ge2_l).
  sp 1; if; last by auto.
  wp; call (_ : true ==> true); first by conseq hypertree_verify_ll.
  inline Observe(A,FC.O_THFC_Default).forge.
  wp; call (_ : true).
  by auto; rewrite /good_transcript; smt().
qed.

lemma observer_preserves_bounded_game
  (A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF {-Observe,-FC.O_THFC_Default}) :
  equiv[BoundedHypertreeGame(A,FC.O_THFC_Default).main ~
        BoundedHypertreeGame(Observe(A),FC.O_THFC_Default).main :
    ={glob A} ==> ={res}].
proof.
  proc; inline Observe(A,FC.O_THFC_Default).choose Observe(A,FC.O_THFC_Default).forge.
  seq 4 5 : (={glob A,glob FC.O_THFC_Default,ml,ps,ad}).
  + wp; call (_ : ={glob FC.O_THFC_Default}); first by sim.
    inline *; by auto.
  seq 5 5 : (={glob A,glob FC.O_THFC_Default,pk,sk,ml,sigl,bad,i}).
  + by sim.
  sp 1 1; if.
  + by auto.
  + wp; call (_ : ={arg} ==> ={res}); first by sim.
    wp; call (_ : true); by auto.
  by auto.
qed.

lemma total_bounded_hypertree_main_event
  (A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF {-FC.O_THFC_Default}) :
  islossless A(FC.O_THFC_Default).forge =>
  equiv[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A, FC.O_THFC_Default).main ~
        BoundedHypertreeGame(A, FC.O_THFC_Default).main :
    ={glob A} ==> res{2} => res{1} /\ ={glob A}].
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

lemma bounded_win_is_observed_good
  (A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF {-Observe,-FC.O_THFC_Default}) &m :
  Pr[BoundedHypertreeGame(A,FC.O_THFC_Default).main() @ &m : res] =
  Pr[BoundedHypertreeGame(Observe(A),FC.O_THFC_Default).main() @ &m :
    res /\ good_transcript Observe.public Observe.messages Observe.signatures].
proof.
  byequiv (_ : ={glob A} ==> res{1} = res{2} /\
    (res{2} => good_transcript Observe.public{2} Observe.messages{2} Observe.signatures{2})) => //.
  conseq (observer_preserves_bounded_game A) _ (bounded_transcript_good A); smt().
  by smt().
qed.

lemma bounded_win_le_total_good
  (A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF {-Observe,-FC.O_THFC_Default}) &m :
  islossless A(FC.O_THFC_Default).forge =>
  Pr[BoundedHypertreeGame(A,FC.O_THFC_Default).main() @ &m : res] <=
  Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(Observe(A),FC.O_THFC_Default).main() @ &m :
    res /\ good_transcript Observe.public Observe.messages Observe.signatures].
proof.
  move=> hll; rewrite (bounded_win_is_observed_good A &m).
  have hol : islossless Observe(A,FC.O_THFC_Default).forge by proc; call hll; auto.
  byequiv (_ : ={glob Observe(A)} ==>
    (res{1} /\ good_transcript Observe.public{1} Observe.messages{1} Observe.signatures{1}) =>
    (res{2} /\ good_transcript Observe.public{2} Observe.messages{2} Observe.signatures{2})) => //.
  symmetry; conseq (total_bounded_hypertree_main_event (Observe(A)) hol); smt().
qed.

op observed_good ['a] (g : 'a * msgFLSLXMSSMTTW list * pkFLSLXMSSMTTW *
  XMSSMT_C_Scheme.sigFLSLXMSSMTTWC list) = good_transcript g.`3 g.`2 g.`4.
section.
declare module A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF {-Observe}.
lemma observed_goodE &m : observed_good (glob Observe(A)){m} =
  good_transcript Observe.public{m} Observe.messages{m} Observe.signatures{m}.
proof. by rewrite /observed_good. qed.
end section.
