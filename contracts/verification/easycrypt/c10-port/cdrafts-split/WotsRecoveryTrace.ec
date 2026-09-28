(* The actual recovery suffixes, independent of an assumed signing opening. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle RawKeygen RawWots PersistentGrind AcceptedContexts.
require import LinearChain RawChainTrace WotsReference WotsChainSplit LinearCollision MemoNodeCollision.

op recovery_endpoint h seed layer tree kp d sigma i =
  linear_value h (chain_input seed layer tree kp i) (nth (nseq 16 0) sigma i)
    (range (digit 3 d i) 7).
op recovery_prefix h seed layer tree kp d sigma n =
  forall i, 0<=i<n =>
    linear_recorded h (chain_input seed layer tree kp i) (nth (nseq 16 0) sigma i)
      (range (digit 3 d i) 7).
op recovery_elements h seed layer tree kp d sigma n =
  map (fun i => pad (recovery_endpoint h seed layer tree kp d sigma i)) (range 0 n).
op recovery_leaf_input h seed layer tree kp d sigma =
  seed ++ address layer tree 1 kp 0 0 0 ++
    flatten (recovery_elements h seed layer tree kp d sigma 43).

lemma recovery_prefix_extends h h' seed layer tree kp d sigma n :
  extends h h' => recovery_prefix h seed layer tree kp d sigma n =>
  recovery_prefix h' seed layer tree kp d sigma n /\
    recovery_elements h' seed layer tree kp d sigma n =
      recovery_elements h seed layer tree kp d sigma n.
proof.
  move=> hh hp.
  have he : forall i, 0<=i<n =>
    linear_recorded h' (chain_input seed layer tree kp i) (nth (nseq 16 0) sigma i)
      (range (digit 3 d i) 7) /\
    recovery_endpoint h' seed layer tree kp d sigma i =
      recovery_endpoint h seed layer tree kp d sigma i.
  + move=> i hi; exact (linear_recorded_extends h h' (chain_input seed layer tree kp i)
      (nth (nseq 16 0) sigma i) (range (digit 3 d i) 7) hh (hp i hi)).
  split; first by rewrite /recovery_prefix; smt().
  rewrite /recovery_elements; apply eq_in_map => i hi; smt(mem_range).
qed.

lemma recovery_prefix_add h seed layer tree kp d sigma n :
  0<=n => recovery_prefix h seed layer tree kp d sigma n =>
  linear_recorded h (chain_input seed layer tree kp n) (nth (nseq 16 0) sigma n)
    (range (digit 3 d n) 7) =>
  recovery_prefix h seed layer tree kp d sigma (n+1).
proof. rewrite /recovery_prefix; smt(). qed.

lemma recovery_elements_step h seed layer tree kp d sigma n :
  0<=n => recovery_elements h seed layer tree kp d sigma (n+1) =
    rcons (recovery_elements h seed layer tree kp d sigma n)
      (pad (recovery_endpoint h seed layer tree kp d sigma n)).
proof. move=> hn; by rewrite /recovery_elements rangeSr 1:hn map_rcons. qed.

lemma linear_value_width h f value indices :
  size value=16 => size (linear_value h f value indices)=16.
proof.
  elim: indices value => [value | index rest ih value].
  + by rewrite /linear_value /=.
  rewrite /linear_value /=; smt(node_width).
qed.

lemma recovery_endpoint_width h seed layer tree kp d sigma i :
  all (fun row => size row=16) sigma =>
  size (recovery_endpoint h seed layer tree kp d sigma i)=16.
proof.
  move=> hw; apply linear_value_width; smt(allP mem_nth nth_out size_nseq).
qed.

lemma recovery_chain_unique h s seed layer tree kp d sigma i :
  !public_node_collision h => wots_prefix h s seed layer tree kp 43 =>
  recovery_prefix h seed layer tree kp d sigma 43 => 0<=i<43 =>
  recovery_endpoint h seed layer tree kp d sigma i = wots_endpoint h s seed layer tree kp i =>
  nth (nseq 16 0) sigma i = wots_partial h s seed layer tree kp i (digit 3 d i).
proof.
  move=> hc hp hr hi he.
  have [hpre [hsuf hv]] := wots_reference_split h s seed layer tree kp i (digit 3 d i)
    hp hi (raw_digit_bounds d i).
  apply (raw_chain_start_unique h seed layer tree kp i (range (digit 3 d i) 7)) => //.
  + exact (hr i hi).
  by rewrite -hv.
qed.
