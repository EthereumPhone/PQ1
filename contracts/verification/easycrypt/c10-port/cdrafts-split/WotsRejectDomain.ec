(* Finite cover of actual serialized count-search inputs, for a fixed public
   seed. All serialized layer/tree/keypair values are covered; no logical
   address restriction or fresh-message assumption reduces the domain. *)
require import AllCore List Distr FMap IntDiv BitEncoding StdOrder.
require import C10RawOracle C10Bytes C10Counter RawKeygen RawSignature RawWots.
require import ByteSession RawCountRecorded RawByteValues RawSignerBytes WotsInputSeparation.
require import WotsAcceptanceMass MemoRejectCompletion.
import BS2Int RField RealOrder.

op wots_context_bytes layer tree kp (message : raw_input) =
  be 4 layer ++ be 8 tree ++ be 4 kp ++ message.
op wots_context_stem (seed context : raw_input) =
  seed ++ take 12 context ++ be 4 0 ++ take 4 (drop 12 context) ++
    be 4 0 ++ be 4 0 ++ be 4 0 ++ pad (drop 16 context).
op wots_context_indices = range 0 (2^256).
op wots_count_schedule (stem : raw_input) n =
  map (fun i => stem ++ be 32 i) (range 0 n).
op wots_domain_exhausted seed n h = exists c,
  List.mem wots_context_indices c /\
  memo_complete_rejection count_accepts h (wots_count_schedule (wots_context_stem seed (be 32 c)) n).
op wots_domain_charge n = (2^256)%r * (1%r-wots_acceptance_mass)^n.

lemma wots_context_bytes_width layer tree kp message : size message=16 =>
  size (wots_context_bytes layer tree kp message)=32.
proof. by move=> hm; rewrite /wots_context_bytes !size_cat !be_width //; smt(). qed.

lemma wots_context_bytes_valid layer tree kp message : byte_values message =>
  byte_values (wots_context_bytes layer tree kp message).
proof. rewrite /wots_context_bytes /byte_values !all_cat; smt(be_bytes). qed.

lemma wots_context_stem_actual seed layer tree kp message :
  wots_context_stem seed (wots_context_bytes layer tree kp message) =
    seed ++ address layer tree 0 kp 0 0 0 ++ pad message.
proof.
  rewrite /wots_context_stem /wots_context_bytes -!catA.
  do 4! (rewrite ?take_cat ?drop_cat ?be_width ?take0 ?drop0 ?cats0 //=).
  by rewrite /address /pad -!catA.
qed.

lemma wots_bytes_rank_width bs : size bs=32 =>
  0<=bs2int (bytes_to_bits bs)<2^256.
proof.
  move=> hw; have hb := bs2int_ge0 (bytes_to_bits bs).
  have ht := bs2int_le2Xs (bytes_to_bits bs).
  move: ht; rewrite bytes_to_bits_size hw /=; smt().
qed.

lemma wots_bytes_rank_roundtrip bs : size bs=32 => byte_values bs =>
  be 32 (bs2int (bytes_to_bits bs))=bs.
proof.
  move=> hw hb; rewrite /be /=.
  have hs : size (bytes_to_bits bs)=256 by rewrite bytes_to_bits_size hw.
  rewrite -hs bs2intK; exact (bytes_bits_roundtrip bs hb).
qed.

lemma wots_context_covered seed layer tree kp message :
  size message=16 => byte_values message => exists c,
    List.mem wots_context_indices c /\
    wots_context_stem seed (be 32 c) = seed ++ address layer tree 0 kp 0 0 0 ++ pad message.
proof.
  move=> hw hb; pose bs := wots_context_bytes layer tree kp message.
  have hs : size bs=32 by exact (wots_context_bytes_width layer tree kp message hw).
  have hv : byte_values bs by exact (wots_context_bytes_valid layer tree kp message hb).
  exists (bs2int (bytes_to_bits bs)); split.
  + rewrite /wots_context_indices mem_range; exact (wots_bytes_rank_width bs hs).
  rewrite (wots_bytes_rank_roundtrip bs hs hv) /bs; apply wots_context_stem_actual.
qed.

lemma wots_context_cardinality : size wots_context_indices=2^256.
proof. rewrite /wots_context_indices size_range; smt(IntOrder.expr_gt0). qed.

lemma wots_count_schedule_size stem n : 0<=n => size (wots_count_schedule stem n)=n.
proof. rewrite /wots_count_schedule size_map size_range; smt(). qed.

lemma wots_count_schedule_unique stem n : 0<=n<=2^256 => uniq (wots_count_schedule stem n).
proof.
  move=> hn; rewrite /wots_count_schedule; apply map_inj_in_uniq; last exact (range_uniq 0 n).
  move=> i j; rewrite !mem_range => hi hj he.
  have hb : be 32 i=be 32 j by smt(catsI).
  apply (be_injective 32 i j); smt().
qed.

lemma wots_count_schedule_actual seed layer tree kp message n :
  wots_count_schedule (wots_context_stem seed (wots_context_bytes layer tree kp message)) n =
    map (wots_count_input seed layer tree kp message) (range 0 n).
proof.
  rewrite /wots_count_schedule wots_context_stem_actual.
  apply eq_map => i; by rewrite /wots_count_input.
qed.

lemma wots_rejection_mass_exact : memo_reject_mass count_accepts = 1%r-wots_acceptance_mass.
proof. by rewrite /memo_reject_mass mu_not full_digest_ll raw_wots_acceptance_mass. qed.

lemma wots_fixed_schedule_bound (A <: Context {-Shared}) stem n &m : 0<=n<=2^256 =>
  Pr[MemoRejectGame(A).run() @ &m :
    memo_complete_rejection count_accepts Shared.history (wots_count_schedule stem n)] <=
    (1%r-wots_acceptance_mass)^n.
proof.
  move=> hn; have hu := wots_count_schedule_unique stem n hn.
  have h := memo_reject_initialized_bound A count_accepts (wots_count_schedule stem n) &m hu.
  by move: h; rewrite wots_rejection_mass_exact wots_count_schedule_size 1:/#.
qed.

lemma wots_context_union_bound (A <: Context {-Shared}) seed n (contexts : int list) &m :
  0<=n<=2^256 =>
  Pr[MemoRejectGame(A).run() @ &m : exists c, List.mem contexts c /\
    memo_complete_rejection count_accepts Shared.history
      (wots_count_schedule (wots_context_stem seed (be 32 c)) n)] <=
    (size contexts)%r * (1%r-wots_acceptance_mass)^n.
proof.
  move=> hn; elim: contexts => [|c rest ih].
  + simplify; byphoare (_ : true ==> false) => //; hoare; trivial.
  have hc := wots_fixed_schedule_bound A (wots_context_stem seed (be 32 c)) n &m hn.
  have he : Pr[MemoRejectGame(A).run() @ &m : exists x, List.mem (c::rest) x /\
      memo_complete_rejection count_accepts Shared.history
        (wots_count_schedule (wots_context_stem seed (be 32 x)) n)] =
    Pr[MemoRejectGame(A).run() @ &m :
      memo_complete_rejection count_accepts Shared.history
        (wots_count_schedule (wots_context_stem seed (be 32 c)) n) \/
      exists x, List.mem rest x /\ memo_complete_rejection count_accepts Shared.history
        (wots_count_schedule (wots_context_stem seed (be 32 x)) n)].
  + rewrite Pr[mu_eq]; smt().
  rewrite he Pr[mu_or]; smt(ge0_mu).
qed.

lemma wots_domain_initialized_bound (A <: Context {-Shared}) seed n &m :
  0<=n<=2^256 =>
  Pr[MemoRejectGame(A).run() @ &m : wots_domain_exhausted seed n Shared.history] <=
    wots_domain_charge n.
proof.
  move=> hn; have h := wots_context_union_bound A seed n wots_context_indices &m hn.
  by move: h; rewrite wots_context_cardinality /wots_domain_exhausted /wots_domain_charge.
qed.
