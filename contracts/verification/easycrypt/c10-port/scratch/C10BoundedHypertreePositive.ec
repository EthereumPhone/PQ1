(* Bounded NPRF hypertree signing. A failed layer returns no signature;
   the remaining layer slots perform no cryptographic work. This uses the
   existing sampled-key model and is not a Rust extraction. *)
require import AllCore List Distr IntDiv BinaryTrees MerkleTrees.
require import C10BoundedHypertree C10BoundedSigning XmssmtCC_All.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme C10BoundedGrind XMSSMT_C_Scheme.

lemma checked_bounded_hypertree_sign_ll : islossless BoundedHypertree.sign.
proof. exact (bounded_hypertree_sign_ll). qed.

lemma checked_bounded_hypertree_sign_size :
  hoare[BoundedHypertree.sign : true ==> res <> None => size (oget res) = d].
proof. exact (bounded_hypertree_sign_size). qed.

lemma checked_total_bounded_hypertree_sign :
  equiv[FL_SL_XMSS_MT_C_ES_NPRF.sign ~ BoundedHypertree.sign :
    ={sk, m, idx} ==> res{2} <> None => res{2} = Some res{1}].
proof. exact (total_bounded_hypertree_sign). qed.

lemma checked_bounded_hypertree_first_failure :
  hoare[BoundedHypertree.sign :
    !prefix_hit sk.`2
      (set_kpidx (set_typeidx
        (set_ltidx sk.`3 0 (Index.val idx %/ l')) chtype) (Index.val idx %% l')) m
    ==> res = None].
proof. exact (bounded_hypertree_first_failure). qed.

lemma checked_bounded_hypertree_win_le_total
  (A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF {-FC.O_THFC_Default}) &m :
  islossless A(FC.O_THFC_Default).forge =>
  Pr[BoundedHypertreeGame(A, FC.O_THFC_Default).main() @ &m : res] <=
  Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A, FC.O_THFC_Default).main() @ &m : res].
proof. exact (bounded_hypertree_win_le_total A &m). qed.
