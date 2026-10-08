(* A fresh-message covered output has distinct accepted-pool witness entries. *)
require import AllCore List Distr FMap BitEncoding.
require import C10RawOracle C10RawGrind C10HashDomains RawKeygen RawForest RawSigner RawSignature.
require import ExposureLog ExposureSupport ExposureWidths ExposureReferences ExposureAccounting ExposureCoverage.
require import ActualExposurePartition ActualWotsCut HmsgShapes HmsgPoolRecords CoverageWitnessCompression PoolCoverageEvent.
import BS2Int.

op logged_message_width (entries : signing_exposure list) =
  forall entry, mem entries entry => size entry.`1=32.
op actual_accepted_coverage h seed root entries (output : raw_input * raw_signature) =
  size output.`1=32 /\ signature_width output.`2 /\ !mem (exposure_messages entries) output.`1 /\
  exists d, accept_digest d /\ h.[hmsg_input seed root (pad output.`2.`1) output.`1]=Some d /\
    returned_coverage h seed root entries d.

lemma hmsg_message_injective seed root r1 r2 m1 m2 :
  size r1=size r2 => hmsg_input seed root r1 m1=hmsg_input seed root r2 m2 => m1=m2.
proof.
  move=> hr; rewrite /hmsg_input -!catA (eqseq_cat seed seed _ _) 1:// /=
    (eqseq_cat root root _ _) 1:// /= (eqseq_cat r1 r2 _ _ hr).
  move=> [_ he]; exact (catIs _ _ (nseq 32 255) he).
qed.
lemma digest_coordinate_equal d e i : size d=256 => size e=256 => 0<=i<12 =>
  forest_index d i=forest_index e i =>
  take 11 (drop (11*i) d)=take 11 (drop (11*i) e).
proof.
  move=> hd he hi hf; apply inj_bs2int_eqsize; last exact hf.
  rewrite !size_take 1..2:/# !size_drop 1..2:/# hd he; smt().
qed.
lemma digest_hypertree_equal d e : size d=256 => size e=256 =>
  hypertree_index d=hypertree_index e => take 18 (drop 143 d)=take 18 (drop 143 e).
proof.
  move=> hd he hf; apply inj_bs2int_eqsize; last exact hf.
  by rewrite !size_take 1..2:/# !size_drop 1..2:/# hd he.
qed.
lemma actual_partition_covered h s seed root entries output :
  actual_exposure_partition h s seed root entries output =>
  actual_covered_output h seed root entries output => actual_accepted_coverage h seed root entries output.
proof. rewrite /actual_exposure_partition /actual_covered_output /actual_accepted_coverage; smt(). qed.

lemma actual_coverage_pool h s seed root entries output keys nodes :
  size seed=32 => size root=32 => valid_history h =>
  exposures_supported h s seed root entries => exposures_width entries => logged_message_width entries =>
  accepted_records h keys nodes => actual_accepted_coverage h seed root entries output => pool_coverage nodes.
proof.
  move=> hs hr hv hex hew hem hrec [hom [hos [hon [d [ha [hd hc]]]]]].
  have hrw : size (pad output.`2.`1)=32 by apply pad_node_width; smt().
  have how : size (hmsg_input seed root (pad output.`2.`1) output.`1)=160
    by exact (hmsg_width _ _ _ _ hs hr hrw hom).
  have hds : size d=256 by move: hv; rewrite /valid_history; smt().
  have [hlen hrecord] := hrec.
  have [target [ht [htk htd]]] := hrecord _ d how ha hd.
  apply (coordinate_witness_pool nodes target ht)=> i hi.
  have [_ [e [he [hht hfi]]]] := hc i hi.
  have [message signature [hm hd']] := he.
  have [ha' _] := logged_digest_references h s seed root entries message signature e hex hm hd'.
  have hm' : size message=32 by exact (hem (message,signature) hm).
  have hsig : signature_width signature by exact (hew (message,signature) hm).
  have hR : size (pad signature.`1)=32 by apply pad_node_width; smt().
  have hiw := hmsg_width seed root (pad signature.`1) message hs hr hR hm'.
  have hes : size e=256 by move: hv; rewrite /valid_history; smt().
  have [k [hk [hkk hkd]]] := hrecord _ e hiw ha' hd'.
  have hnew : message<>output.`1 by have hnm:=exposure_new_message entries output.`1; smt().
  have hdistinct : k<>target.
  + have hinput : hmsg_input seed root (pad signature.`1) message<>
      hmsg_input seed root (pad output.`2.`1) output.`1 by
      smt(hmsg_message_injective).
    smt().
  exists k; rewrite /coordinate_witness hkd htd.
  have hh := digest_hypertree_equal e d hes hds hht.
  have hh' := digest_coordinate_equal e d i hes hds hi hfi.
  smt().
qed.
