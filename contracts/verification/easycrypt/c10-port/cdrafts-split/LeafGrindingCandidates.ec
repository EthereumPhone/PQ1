(* Exact suffix guesses of actual finite grinder inputs. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter C10HashDomains C10Representation.
require import RawKeygen C10CallerInputBridge LeafCommitmentHybrid LeafCandidateCount.

lemma leaf_counter_candidate_fixed prefix c : 0<=c<4294967296 =>
  !leaf_variable_query (prefix ++ be 32 c).
proof.
  move=> hc; rewrite (caller_counter_slot c hc).
  apply leaf_variable_zero_counter; by rewrite /u32_bytes size_rev size_mkseq.
qed.
lemma leaf_wots_trial_fixed seed layer tree kp message c : 0<=c<signing_budget =>
  !leaf_variable_query (seed ++ address layer tree 0 kp 0 0 0 ++ pad message ++ be 32 c).
proof.
  move=> hc; apply leaf_counter_candidate_fixed; move: hc; rewrite /signing_budget; smt().
qed.
lemma leaf_hmsg_candidate_fixed seed root random message :
  !leaf_variable_query (hmsg_input seed root random message).
proof. rewrite /hmsg_input; exact (leaf_variable_ff_block (seed ++ root ++ random ++ message)). qed.
