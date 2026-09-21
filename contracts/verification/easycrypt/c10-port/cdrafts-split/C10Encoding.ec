(* Concrete consumer encoding and uniform-digest acceptance.
   The uniform experiment below is explicit: no SHA-256 property is assumed. *)
require import AllCore List Distr DList DBool BitEncoding StdBigop IntDiv StdOrder.
require import SPHINCS_PLUS C10DeployedInstance C10DigitUniform C10Surface C10SurfaceKernel.
require import WOTS_C_Real RadixEncoding.
import FSSLXMTWES FSSLXMTWES.WTWES EmsgWOTS BS2Int Bigint Bigint.BIA.

lemma deployed_message_bits (m : msgWOTS) : size (MDigestBlock.val m) = 256.
proof. by rewrite MDigestBlock.valP /n_m n_val. qed.

lemma deployed_digit (m : msgWOTS) (i : int) :
  0 <= i < 43 => BaseW.val (encode_msgWOTS m).[i] =
    RadixEncoding.digit 3 (MDigestBlock.val m) i.
proof. by move=> hi; rewrite encode_msgWOTS_digit 1:len_val // log2_w_val. qed.

(* Same per-chain integer formula as the Aeneas/Lean extract_digits_spec.
   The two proof assistants are replayed independently, not implicitly linked. *)
lemma deployed_digit_integer (m : msgWOTS) (i : int) :
  0 <= i < 43 => BaseW.val (encode_msgWOTS m).[i] =
   (bs2int (MDigestBlock.val m) %/ 2 ^ (3*i)) %% 8.
proof.
  by move=> hi; rewrite deployed_digit // digit_integer 1,2:/#
    1:deployed_message_bits 1:/# pow2_3.
qed.

lemma deployed_witness_bits : MDigestBlock.val tgt_witness = c10_witness_bits.
proof.
  rewrite /tgt_witness MDigestBlock.insubdK.
  + by rewrite size_mkseq /n_m n_val.
  by rewrite /c10_witness_bits /c10_n_m /n_m n_val.
qed.

lemma deployed_target_205 : target_sum = 205.
proof.
  rewrite /target_sum /digitsum len_val.
  have -> : bigi predT (fun i => BaseW.val (encode_msgWOTS tgt_witness).[i]) 0 43
      = bigi predT (c10_digit_at c10_witness_bits) 0 c10_len.
  + rewrite /c10_len; apply eq_big_int => i hi /=.
    by rewrite deployed_digit // deployed_witness_bits digit3 /c10_digit_at /c10_log2_w.
  exact c10_deployed_encoder_attains_target.
qed.

lemma consumer_digit_sum (m : msgWOTS) :
  digitsum (encode_msgWOTS m) = sumz (RadixEncoding.digits 3 43 (MDigestBlock.val m)).
proof.
  rewrite /digitsum len_val /RadixEncoding.digits /mkseq sumzE big_map.
  apply eq_big_int => i hi /=.
  by rewrite deployed_digit.
qed.

lemma consumer_predicate (m : msgWOTS) :
  predC m = (sumz (RadixEncoding.digits 3 43 (MDigestBlock.val m)) = 205).
proof. by rewrite /predC /P deployed_target_205 consumer_digit_sum. qed.

op uniform_digest : msgWOTS distr = dmap (dlist dbool 256) MDigestBlock.insubd.

lemma uniform_digest_ll : is_lossless uniform_digest.
proof. by apply dmap_ll; apply dlist_ll; exact dbool_ll. qed.

lemma uniform_digest_full : is_full uniform_digest.
proof.
  move=> m; rewrite /uniform_digest supp_dmap.
  exists (MDigestBlock.val m); rewrite MDigestBlock.valKd /=.
  rewrite supp_dlist 1:// deployed_message_bits /=.
  by apply allP => b hb; exact supp_dbool.
qed.

lemma uniform_digest_uniform : is_uniform uniform_digest.
proof.
  apply dmap_uni_in_inj.
  + move=> x y hx hy he.
    have sx := supp_dlist_size dbool 256 x _ hx; first done.
    have sy := supp_dlist_size dbool 256 y _ hy; first done.
    rewrite -(MDigestBlock.insubdK x) 1:/n_m 1:n_val 1:sx //.
    by rewrite -(MDigestBlock.insubdK y) 1:/n_m 1:n_val 1:sy // he.
  exact (dlist_uni _ _ dbool_uni).
qed.

(* The existing exact digit-vector census is now consumed by the actual gate. *)
lemma consumer_uniform_acceptance :
  mu uniform_digest predC = 22169393903687611906220091621190388%r / (8 ^ 43)%r.
proof.
  rewrite /uniform_digest dmapE.
  have -> : mu (dlist dbool 256) (predC \o MDigestBlock.insubd)
    = mu (dlist dbool 256) (fun bs => sumz (RadixEncoding.digits 3 43 bs) = 205).
  + apply mu_eq_support => bs hbs; rewrite /(\o) consumer_predicate MDigestBlock.insubdK //.
    by rewrite /n_m n_val; exact (supp_dlist_size dbool 256 bs _ hbs).
  rewrite (_ : 256 = 3*43+127) 1:// uniform_digit_sum 1,2://.
  by rewrite c10_surface_count.
qed.


lemma consumer_uniform_acceptance_bits :
  mu uniform_digest predC = 22169393903687611906220091621190388%r / (2 ^ 129)%r.
proof.
  have hspace : 8 ^ 43 = 2 ^ 129 by exact c10_codeword_space.
  by rewrite consumer_uniform_acceptance hspace.
qed.
