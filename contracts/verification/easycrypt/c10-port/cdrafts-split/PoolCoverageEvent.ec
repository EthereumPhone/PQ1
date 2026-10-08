(* Finite witness event for coverage among accepted H_msg samples. *)
require import AllCore List Distr DList StdBigop Ring.
require import C10RawOracle CountDS CoverageAssignment SelectedCoverageMass AcceptedPrefixSampling.

op pool_coverage (nodes : digest list) =
  exists target witnesses f,
    1<=size witnesses<=12 /\ uniq (target::witnesses) /\
    all (fun i=>0<=i<size nodes) (target::witnesses) /\
    coverage_assignment (size witnesses) f /\ assignment_pool_event target witnesses f nodes.
op pool_coverage_j n j (nodes : digest list) =
  has (fun target => has (fun witnesses => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes)
    (words 12 j)) (words j n)) (range 0 n).
op pool_coverage_enumerated n (nodes : digest list) =
  has (fun j => pool_coverage_j n j nodes) (range 1 13).

lemma words_size n b : 0<=n => 0<=b => size (words n b)=b^n.
proof.
  move=> hn hb; elim: n hn => [|n hn ih].
  + by rewrite words0 /= IntID.expr0.
  rewrite wordsS // size_allpairs size_range ih // IntID.exprS //; smt().
qed.
lemma pool_coverage_enumeration n nodes : size nodes=n =>
  pool_coverage nodes=pool_coverage_enumerated n nodes.
proof.
  move=> hn; rewrite /pool_coverage /pool_coverage_enumerated hasP eq_iff; split.
  + move=> [t w f [hj [hu [hb [hf he]]]]].
    exists (size w); rewrite mem_range /=; split; first smt().
    rewrite /pool_coverage_j hasP; exists t; rewrite mem_range /=.
    move: hb=> /= [ht hw]; split; first smt().
    rewrite hasP; exists w; rewrite mem_words 1:size_ge0 /= /is_digit.
    split; first by smt().
    rewrite hasP; exists f; rewrite mem_words // /=; smt().
  move=> [j [hj he]]; move: hj; rewrite mem_range=> hj.
  move: he; rewrite /= /pool_coverage_j hasP.
  move=> [t [ht he]].
  move: he; rewrite /= hasP.
  move=> [w [hw he]].
  move: he; rewrite /= hasP.
  move=> [f [hf he]].
  move: ht hw hf; rewrite mem_range (mem_words j n _) 1:/# (mem_words 12 j _) // /is_digit=> ht [hs hw] hf.
  exists t w f; rewrite hs /= /coverage_assignment; smt().
qed.
lemma assignment_pool_append target witnesses f nodes more :
  all (fun i=>0<=i<size nodes) (target::witnesses) =>
  assignment_pool_event target witnesses f nodes =>
  assignment_pool_event target witnesses f (nodes++more).
proof.
  move=> /= [ht hw] he; rewrite /assignment_pool_event=> g hg.
  have hi : 0<=nth 0 witnesses g<size nodes by move: hw=> /allP h; apply h; exact (mem_nth _ _ _ hg).
  rewrite !nth_cat (: target<size nodes) 1:/# (: nth 0 witnesses g<size nodes) 1:/#.
  exact (he g hg).
qed.
lemma pool_coverage_extension : extension_closed pool_coverage.
proof.
  move=> nodes more [t w f [hj [hu [hb [hf he]]]]].
  exists t w f; split=> //; split=> //; split.
  + apply/allP=> i hi; have h : 0<=i<size nodes by move: hb=> /allP; apply.
    rewrite size_cat; smt(size_ge0).
  split=> //; exact (assignment_pool_append t w f nodes more hb he).
qed.
