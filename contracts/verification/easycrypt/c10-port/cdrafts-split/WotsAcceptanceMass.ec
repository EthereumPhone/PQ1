(* The actual raw WOTS acceptance test on a fresh full digest. *)
require import AllCore List Distr DList DBool Ring BitEncoding RadixEncoding StdOrder StdBigop RealSeries.
require import C10RawOracle C10Randomizer RawWots WotsDigitOrder EncodingDistribution.
require import CountDS C10Surface C10SurfaceKernel.
import BS2Int RField RealOrder Bigreal BRA.

op digit_distribution = dmap (dlist dbool 3) bs2int.

lemma digit_distribution_support x :
  x \in digit_distribution <=> 0<=x<8.
proof.
  rewrite /digit_distribution supp_dmap; split.
  + move=> [bs [hb ->]].
    have hs := supp_dlist_size dbool 3 bs _ hb; first done.
    have hp := bs2int_le2Xs bs; rewrite hs in hp.
    have he : 2^3=8 by rewrite (_:3=2+1) 1:// IntID.exprS 1:// IntID.expr2.
    smt(bs2int_ge0).
  move=> hx; exists (int2bs 3 x); split.
  + rewrite supp_dlist 1:// size_int2bs /=; smt(dbool_fu allP).
  rewrite int2bsK 1://.
  + by rewrite (_:3=2+1) 1:// IntID.exprS 1:// IntID.expr2.
  by [].
qed.

lemma digit_distribution_mass x :
  0<=x<8 => mu1 digit_distribution x=(1%r/2%r)^3.
proof.
  move=> hx; rewrite /digit_distribution dmap1E.
  have he : 2^3=8 by rewrite (_:3=2+1) 1:// IntID.exprS 1:// IntID.expr2.
  have hm : mu (dlist dbool 3) (fun bs=>bs2int bs=x)=
    mu1 (dlist dbool 3) (int2bs 3 x).
  + apply mu_eq_support=> bs hb; have hs := supp_dlist_size dbool 3 bs _ hb; first done.
    rewrite /pred1 eq_iff; split=> hd.
    - by rewrite -hd -hs bs2intK.
    smt(int2bsK).
  rewrite /pred1 /= hm.
  have h := bool_word_mass (int2bs 3 x).
  by move: h; rewrite size_int2bs /=.
qed.

lemma digits_distribution n : 0<=n =>
  dmap (dlist dbool (3*n)) (digits 3 n)=dlist digit_distribution n.
proof.
  elim: n => [|n hn ih].
  + by rewrite /= (dlist0 dbool 0) // dmap_dunit /digits mkseq0 (dlist0 digit_distribution 0).
  rewrite (: 3*(n+1)=3+3*n) 1:/# dlist_add 1,2:/# dmap_comp.
  rewrite (eq_dmap_in _ _ (fun xy : bool list * bool list => bs2int xy.`1 :: digits 3 n xy.`2)).
  + move=> [lo hi] /= /supp_dprod [hlo hhi]; rewrite /(\o) /=.
    apply digits_cat => //; exact (supp_dlist_size dbool 3 lo _ hlo).
  rewrite dlistS 1:hn -ih /digit_distribution dmap_dprod /= dmap_comp.
  by [].
qed.

lemma raw_digits_encoding d : raw_digits (encoding_bits d)=raw_digits d.
proof.
  apply (eq_from_nth 0); first by rewrite /raw_digits /digits !size_mkseq.
  move=> i; rewrite /raw_digits /digits size_mkseq /= => hi.
  rewrite !nth_mkseq 1,2:/# !digit3 /encoding_bits !nth_mkseq 1..3:/#.
  by [].
qed.

lemma raw_digits_uniform :
  dmap full_digest raw_digits=dlist digit_distribution 43.
proof.
  rewrite -digits_distribution 1:// /raw_digits -/(raw_digits _) /encoding_distribution.
  have he : dmap full_digest raw_digits=dmap (dmap full_digest encoding_bits) raw_digits.
  + rewrite dmap_comp; apply eq_dmap=> d; by rewrite /(\o) raw_digits_encoding.
  by rewrite he encoding_uniform /encoding_distribution.
qed.

lemma digit_word_mass xs : all (is_digit 8) xs =>
  mu1 (dlist digit_distribution (size xs)) xs=(1%r/2%r)^(3*size xs).
proof.
  elim: xs=> [|x xs ih]; first by rewrite /= dlist01E 1:// expr0.
  move=> [hx ht]; have hm := ih ht.
  rewrite dlistS1E (digit_distribution_mass x hx) hm.
  by rewrite /= (: 3*(1+size xs)=3+3*size xs) 1:/# exprD 1,2:/#.
qed.

lemma digit_sum_mass n s : 0<=n =>
  mu (dlist digit_distribution n) (fun xs=>sumz xs=s)=
    (count_ds n 8 s)%r*(1%r/2%r)^(3*n).
proof.
  move=> hn; pose ws := filter (fun xs=>sumz xs=s) (words n 8).
  have hw := count_ds_counts_digit_vectors n 8 s hn.
  have he : mu (dlist digit_distribution n) (fun xs=>sumz xs=s)=
    mu (dlist digit_distribution n) (mem ws).
  + apply mu_eq_support=> xs hx.
    have [hs ha] : size xs=n /\ all (support digit_distribution) xs
      by move: hx; rewrite supp_dlist.
    have hd : all (is_digit 8) xs.
    - apply/allP=> x hm; have hx' : x \in digit_distribution by smt(allP).
      by move: hx'; rewrite digit_distribution_support /is_digit.
    rewrite /ws mem_filter (mem_words n 8 hn); smt().
  rewrite he mu_mem_uniq; first smt().
  rewrite (@BRA.eq_big_seq _ (fun _=> (1%r/2%r)^(3*n))).
  + move=> xs hx; have [hs [ha hp]] : size xs=n /\ all (is_digit 8) xs /\ sumz xs=s by smt().
    have hm := digit_word_mass xs ha.
    by move: hm; rewrite hs.
  have hsize : size ws=count_ds n 8 s by smt().
  by rewrite Bigreal.sumr_const count_predT hsize.
qed.

op wots_acceptance_mass = (count_ds 43 8 205)%r*(1%r/2%r)^129.

lemma raw_wots_acceptance_mass :
  mu full_digest count_accepts=wots_acceptance_mass.
proof.
  have h := digit_sum_mass 43 205 _; first done.
  by move: h; rewrite -raw_digits_uniform dmapE /(\o) /count_accepts /wots_acceptance_mass.
qed.

lemma wots_acceptance_mass_value :
  wots_acceptance_mass=22169393903687611906220091621190388%r*(1%r/2%r)^129.
proof. by rewrite /wots_acceptance_mass c10_surface_count. qed.

lemma wots_acceptance_mass_bounds : 0%r<=wots_acceptance_mass<=1%r.
proof. rewrite -raw_wots_acceptance_mass; exact (mu_bounded full_digest count_accepts). qed.

lemma wots_acceptance_mass_positive : 0%r<wots_acceptance_mass.
proof.
  rewrite wots_acceptance_mass_value; apply mulr_gt0; first smt().
  apply expr_gt0; smt().
qed.

lemma raw_digits_atom d :
  mu full_digest (fun e=>raw_digits d=raw_digits e)=(1%r/2%r)^129.
proof.
  have hs : size (raw_digits d)=43 by rewrite /raw_digits /digits size_mkseq.
  have ha : all (is_digit 8) (raw_digits d).
  + apply/allP=> x; rewrite /raw_digits /digits mkseqP; move=> [i [hi ->]].
    rewrite /is_digit; smt(raw_digit_bounds).
  have h := digit_word_mass (raw_digits d) ha.
  move: h; rewrite hs -raw_digits_uniform dmap1E /pred1 /(\o) /=.
  move=> h; rewrite -h; apply mu_eq=> e; smt().
qed.

lemma accepted_encoding_match_mass d :
  mu full_digest (fun e=>count_accepts d /\ count_accepts e /\ raw_digits d=raw_digits e)=
    (if count_accepts d then (1%r/2%r)^129 else 0%r).
proof.
  case (count_accepts d)=> hd.
  + rewrite (mu_eq _ _ (fun e=>raw_digits d=raw_digits e)).
    - move=> e; move: hd; rewrite /count_accepts; smt().
    exact (raw_digits_atom d).
  apply mu0_false=> e; smt().
qed.

lemma accepted_encoding_pair_mass :
  mu (full_digest `*` full_digest) (fun (de : digest * digest)=>
    count_accepts de.`1 /\ count_accepts de.`2 /\ raw_digits de.`1=raw_digits de.`2)=
    wots_acceptance_mass*(1%r/2%r)^129.
proof.
  rewrite dprod_partition /=.
  have he : (fun d=>mu full_digest (fun e=>count_accepts d /\ count_accepts e /\ raw_digits d=raw_digits e)*mu1 full_digest d)=
    (fun d=>(1%r/2%r)^129*(if count_accepts d then mu1 full_digest d else 0%r)).
  + apply fun_ext=> d; rewrite accepted_encoding_match_mass; smt().
  rewrite he sumZ -muE raw_wots_acceptance_mass; ring.
qed.
