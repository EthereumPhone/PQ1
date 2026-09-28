(* The actual software shuffle visits every index exactly once, including its
   zero-seed identity branch. No uniform-permutation claim is needed. *)
require import AllCore List IntDiv.
require import C10RawOracle C10Bytes KeygenPrefixes RawShuffle ShuffleBytes ShuffleSwap.

lemma raw_shuffle_permutation (O <: PreparationOracle) n0 :
  islossless O.hash =>
  hoare [RawShuffle(O).permutation : n = n0 /\ 0 <= n0 ==> perm_eq res (range 0 n0)].
proof.
  move=> hh; proc; sp 1; if; last by auto; smt(perm_eq_refl).
  while (n=n0 /\ perm_eq order (range 0 n) /\ 0 <= i < n /\
    all (fun b => 0 <= b < 256) stream).
  + auto; move=> &m [hinv hguard].
    have hs : size order{m} = n{m} by smt(perm_eq_size size_range).
    have hlo := shuffle_nth_byte stream{m} pos{m} _; first smt().
    have hhi := shuffle_nth_byte stream{m} (pos{m}+1) _; first smt().
    have hj := shuffle_mulhi_range (nth 0 stream{m} pos{m})
      (nth 0 stream{m} (pos{m}+1)) i{m} hlo hhi _; first smt().
    have hp := swap_put_permutation 0 order{m} i{m}
      (((nth 0 stream{m} (pos{m}+1)*256+nth 0 stream{m} pos{m})*(i{m}+1)) %/ 65536) _ _;
      first 2 smt().
    smt(perm_eq_trans).
  wp; while (n=n0 /\ perm_eq order (range 0 n) /\ 1 < n /\
    all (fun b => 0 <= b < 256) stream).
  + wp; call (_ : true ==> true); first by conseq hh.
    auto; smt(all_cat shuffle_bytes_valid).
  auto; smt(perm_eq_refl).
qed.
