(* A conservative count-input domain. It covers full-u32 WOTS inputs
   for arbitrary message lengths while retaining all raw client queries. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawWots RawCountRecorded NodeQueryDomain IndependentWidths HmsgShapes ClientGuessCandidates.
require import RawSignature C10Representation C10CallerInputBridge LeafCommitmentHybrid LeafCandidateCount.
require import WotsEncodingSplit WotsDigitOrder.
import RealOrder.

op wots_count_query (x : raw_input) =
  112<=size x /\ take 4 (drop 44 x)=be 4 0 /\
    leaf_suffix_candidate x=nseq 16 0.

lemma actual_count_query_shape seed layer tree kp message count :
  size seed=32 => 0<=count<4294967296 =>
  wots_count_query (wots_count_input seed layer tree kp message count).
proof.
  move=> hs hc.
  have hk := node_input_kind seed layer tree 0 kp 0 0 0 (pad message ++ be 32 count) hs.
  have ht : leaf_suffix_candidate (wots_count_input seed layer tree kp message count)=nseq 16 0.
  + rewrite /wots_count_input (caller_counter_slot count hc).
    apply leaf_suffix_zero_counter; by rewrite /u32_bytes size_rev size_mkseq.
  rewrite /wots_count_query; split.
  + rewrite /wots_count_input /pad !size_cat ?raw_address_width ?be_width // ?size_nseq ?hs.
    smt(size_ge0).
  split; last exact ht.
  by rewrite /wots_count_input -catA hk.
qed.

lemma count_query_no_hmsg seed root random message :
  !wots_count_query (C10HashDomains.hmsg_input seed root random message).
proof.
  rewrite /wots_count_query /C10HashDomains.hmsg_input leaf_suffix_ff_block.
  have hn : nseq 16 255<>nseq 16 0 by smt(nth_nseq).
  smt().
qed.

lemma count_query_no_short x : size x<112 => !wots_count_query x.
proof. by rewrite /wots_count_query; smt(). qed.

lemma count_query_no_other_kind seed layer tree kind kp ci cp ha payload :
  size seed=32 => be 4 kind<>be 4 0 =>
  !wots_count_query (seed ++ address layer tree kind kp ci cp ha ++ payload).
proof.
  move=> hs hk; rewrite /wots_count_query (node_input_kind seed layer tree kind kp ci cp ha payload hs).
  smt().
qed.
