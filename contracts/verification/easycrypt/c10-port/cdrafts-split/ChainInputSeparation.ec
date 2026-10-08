(* The encoded step distinguishes chain-table entries even when their node values coincide. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawSignature RawChainTrace ForsInputSeparation.

lemma chain_step_input_injective seed layer tree kp index j value j' value' :
  0<=j<4294967296 => 0<=j'<4294967296 =>
  chain_input seed layer tree kp index j value=chain_input seed layer tree kp index j' value' => j=j'.
proof.
  move=> hj hj' he.
  have hp : be 4 j ++ be 4 0 ++ pad value=be 4 j' ++ be 4 0 ++ pad value'.
  + move: he; rewrite /chain_input /address -!catA; smt(catsI).
  have ht : take 4 (be 4 j ++ be 4 0 ++ pad value)=take 4 (be 4 j' ++ be 4 0 ++ pad value') by rewrite hp.
  have hw : be 4 j=be 4 j' by move: ht; rewrite -!catA !take_size_cat 1,2:be_width.
  exact (be4_injective j j' hj hj' hw).
qed.

op chain_steps_before (h : (raw_input,digest) fmap) seed layer tree kp index n =
  forall x, x \in h => exists j value, 0<=j<n /\ x=chain_input seed layer tree kp index j value.

lemma chain_steps_empty seed layer tree kp index :
  chain_steps_before empty seed layer tree kp index 0.
proof. rewrite /chain_steps_before; smt(mem_empty). qed.

lemma chain_next_fresh h seed layer tree kp index j value :
  0<=j<4294967296 => chain_steps_before h seed layer tree kp index j =>
  chain_input seed layer tree kp index j value \notin h.
proof.
  move=> hj hh; rewrite /chain_steps_before in hh.
  smt(chain_step_input_injective).
qed.

lemma chain_steps_insert h seed layer tree kp index j value d :
  0<=j => chain_steps_before h seed layer tree kp index j =>
  chain_steps_before h.[chain_input seed layer tree kp index j value <- d] seed layer tree kp index (j+1).
proof.
  move=> hj hh; rewrite /chain_steps_before => x hx.
  case (x=chain_input seed layer tree kp index j value) => he.
  + exists j value; smt().
  have hm : x \in h by smt(mem_set).
  have [k v [hk hv]] := hh x hm; exists k v; smt().
qed.
