(* Hash-width separation used by the accepted H_msg-entry census. *)
require import AllCore List Distr DList.
require import C10RawOracle C10Bytes C10Randomizer C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawSignature RawShuffle ClientGuessCandidates IndependentWidths.
require import AcceptedPrefixSampling HmsgMemoOracle HmsgMemoFacts.

module HmsgPreparation = PreparationView(HmsgMemo(AcceptedSamples)).

lemma pad_node_width x : size x=16 => size (pad x)=32.
proof. by move=> hx; rewrite /pad size_cat size_nseq hx. qed.
lemma hash_chain_width seed a x : size seed=32 => size a=32 => size x=16 =>
  size (seed++a++pad x)=96.
proof. move=> hs ha hx; by rewrite /pad !size_cat !size_nseq hs ha hx. qed.
lemma hash_pair_width seed a x y : size seed=32 => size a=32 => size x=16 => size y=16 =>
  size (seed++a++pad x++pad y)=128.
proof. move=> hs ha hx hy; by rewrite /pad !size_cat !size_nseq hs ha hx hy. qed.
lemma hash_count_width seed a x nonce : size seed=32 => size a=32 => size x=16 =>
  size (seed++a++pad x++be 32 nonce)=128.
proof. move=> hs ha hx; by rewrite /pad !size_cat !size_nseq hs ha hx be_width. qed.
lemma wide_flatten_width rows n : size rows=n => all (fun (x : raw_input) => size x=32) rows =>
  size (flatten rows)=32*n.
proof.
  move=> hn ha; rewrite (size_flatten_ctt 32); last by rewrite hn.
  by move: ha=> /allP; apply.
qed.
lemma padded_flatten_width rows n : rows_width n rows => size (flatten (map pad rows))=32*n.
proof.
  move=> [hn ha]; apply (wide_flatten_width _ n); first by rewrite size_map hn.
  apply/allP => x /mapP [y [hy ->]]; apply pad_node_width.
  move: ha=> /allP h; exact (h y hy).
qed.

lemma all_nth_width xs i : all (fun (x : raw_input) => size x=16) xs =>
  size (nth (nseq 16 0) xs i)=16.
proof.
  move=> /allP hx; case (0<=i<size xs)=> hi.
  + by apply hx; apply mem_nth.
  by rewrite nth_out // size_nseq.
qed.
lemma rows_nth_width n xs i : rows_width n xs => size (nth (nseq 16 0) xs i)=16.
proof. move=> [_ hx]; exact (all_nth_width xs i hx). qed.

lemma hmsg_wots_private c :
  hoare [HmsgPreparation.wots :
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\ size res=256].
proof. proc; call (hmsg_derive_width_count c); auto. qed.
lemma hmsg_fors_private c :
  hoare [HmsgPreparation.fors :
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\ size res=256].
proof. proc; call (hmsg_derive_width_count c); auto. qed.

lemma hmsg_shuffle_derive c :
  hoare [RawShuffle(HmsgPreparation).derive :
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\
    size seed=32 /\ size label<=7 ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\ size res=32].
proof.
  proc; sp 1; if; last by auto; smt(size_nseq).
  wp; call (hmsg_nonmessage_width c); auto.
  move=> &hr [[_ [hv [hc [hs hl]]]] _]; split.
  + rewrite /shuffle_tag !size_cat /= hs; smt().
  move=> _ d count history [hv' [hc' hd]].
  by rewrite bits_to_bytes_size hd /= hv' hc'.
qed.
lemma hmsg_shuffle_permutation c :
  hoare [RawShuffle(HmsgPreparation).permutation :
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\ size seed=32 ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c].
proof.
  proc; sp 1; if; last by auto.
  while (independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c);
    first by auto.
  wp; while (independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls=c /\ size seed=32).
  + wp; call (hmsg_nonmessage_width c); auto.
    move=> &hr [[hv [hc hs]] hb]; split.
    - rewrite /fisher_tag !size_cat be_width //= hs; smt().
    by move=> _ d count history [hv' [hc' hd]]; rewrite hv' hc' hs.
  auto.
qed.
