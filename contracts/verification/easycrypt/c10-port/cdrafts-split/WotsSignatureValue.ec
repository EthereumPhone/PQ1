(* A signature opens the fixed reference chains at their message digits. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle RawKeygen WotsChainSplit.

op wots_signature h s seed layer tree kp d (sigma : raw_input list) =
  size sigma = 43 /\ forall i, 0 <= i < 43 =>
    nth (nseq 16 0) sigma i = wots_partial h s seed layer tree kp i (digit 3 d i).

op visited_signature h s seed layer tree kp d order step (sigma : raw_input list) =
  size sigma = 43 /\ forall i, i \in take step order =>
    nth (nseq 16 0) sigma i = wots_partial h s seed layer tree kp i (digit 3 d i).

lemma visited_signature_empty h s seed layer tree kp d order :
  visited_signature h s seed layer tree kp d order 0 (nseq 43 (nseq 16 0)).
proof. by rewrite /visited_signature size_nseq take0 /=. qed.

lemma visited_signature_complete h s seed layer tree kp d order sigma :
  perm_eq order (range 0 43) => visited_signature h s seed layer tree kp d order 43 sigma =>
  wots_signature h s seed layer tree kp d sigma.
proof.
  rewrite /visited_signature /wots_signature => hp [hs hv]; split; first exact hs.
  have hsize : size order=43 by smt(perm_eq_size size_range).
  smt(take_size perm_eq_mem mem_range).
qed.

lemma visited_signature_step h s seed layer tree kp d order step sigma value :
  perm_eq order (range 0 43) => 0 <= step < 43 =>
  visited_signature h s seed layer tree kp d order step sigma =>
  value = wots_partial h s seed layer tree kp (nth 0 order step) (digit 3 d (nth 0 order step)) =>
  visited_signature h s seed layer tree kp d order (step+1) (put sigma (nth 0 order step) value).
proof.
  move=> hp hstep [hs hv] he.
  have hsize : size order=43 by smt(perm_eq_size size_range).
  have hi : 0 <= nth 0 order step < 43 by smt(mem_nth perm_eq_mem mem_range).
  rewrite /visited_signature size_put hs; split; first by [].
  move=> i hm.
  have ht : take (step+1) order = rcons (take step order) (nth 0 order step)
    by apply take_nth; smt().
  rewrite nth_put 1:/#; smt(mem_rcons).
qed.
