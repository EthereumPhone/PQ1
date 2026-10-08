(* A fixed assignment of all ordinary FORS coordinates to independent witnesses. *)
require import AllCore List Distr DList DBool StdBigop StdOrder.
require import C10RawOracle C10Randomizer AcceptedDigestDistribution AcceptedCoordinateLaw CountDS.
import RField RealOrder Bigreal Bigreal.BRM.

op coverage_assignment j (f : int list) = size f=12 /\ all (is_digit j) f.
op group_coordinate f g (target : digest) i chunk =
  nth 0 f i=g => chunk=take 11 (drop (11*i) target).
op group_event f g target d =
  coordinate_predicate (group_coordinate f g target) d /\
  take 18 (drop 143 d)=take 18 (drop 143 target).
op group_mass f g =
  (bigi predT (fun i => if nth 0 f i=g then (1%r/2%r)^11 else 1%r) 0 12)*(1%r/2%r)^18.

lemma group_coordinate_mass f g target i : size target=256 => 0<=i<12 =>
  mu (dlist dbool 11) (group_coordinate f g target i) =
    if nth 0 f i=g then (1%r/2%r)^11 else 1%r.
proof.
  move=> ht hi; rewrite /group_coordinate.
  case (nth 0 f i=g) => hf; rewrite /=.
  + have hs : size (take 11 (drop (11*i) target))=11
      by rewrite size_take 1:/# size_drop 1:/# ht; smt().
    change (mu1 (dlist dbool 11) (take 11 (drop (11*i) target))=(1%r/2%r)^11).
    by rewrite -{1}hs bool_word_mass hs.
  exact (dlist_ll _ _ dbool_ll).
qed.

lemma coverage_group_mass f g target : size target=256 =>
  mu accepted_digest (group_event f g target)=group_mass f g.
proof.
  move=> ht; rewrite /group_event accepted_joint_coordinate_mass.
  + by rewrite size_take 1:/# size_drop 1:/# ht.
  rewrite /group_mass /coordinate_mass; congr; apply eq_big_seq => i /mem_range hi /=.
  exact (group_coordinate_mass f g target i ht hi).
qed.

lemma product_constant (v : real) n : 0<=n =>
  bigi predT (fun _ => v) 0 n=v^n.
proof.
  elim n => [|n hn ih]; first by rewrite big_geq // expr0.
  by rewrite big_int_recr 1:hn /= ih exprS 1:hn; ring.
qed.
lemma product_single (v : real) j k : 0<=k<j =>
  bigi predT (fun g => if k=g then v else 1%r) 0 j=v.
proof.
  move=> hk; rewrite (bigD1 _ _ k) 1:mem_range 1:hk 1:range_uniq /=.
  have hr : big (predC1 k) (fun g => if k=g then v else 1%r) (range 0 j)=1%r.
  + apply big1 => g; rewrite /predC1; smt().
  by rewrite hr mulr1.
qed.

lemma assignment_product_mass j f : 0<=j => coverage_assignment j f =>
  bigi predT (fun g => group_mass f g) 0 j=(1%r/2%r)^(132+18*j).
proof.
  move=> hj [hf hall]; rewrite /group_mass big_split product_constant 1:hj.
  rewrite (exchange_big predT predT
    (fun g i => if nth 0 f i=g then (1%r/2%r)^11 else 1%r)).
  have hp : bigi predT
    (fun i => bigi predT (fun g => if nth 0 f i=g then (1%r/2%r)^11 else 1%r) 0 j) 0 12 =
    ((1%r/2%r)^11)^12.
  + rewrite -(product_constant ((1%r/2%r)^11) 12 _) 1:/#; apply eq_big_seq => i /mem_range hi /=.
    apply product_single.
    have hm : nth 0 f i \in f by apply mem_nth; smt().
    move: hall=> /allP h; have := h _ hm; by rewrite /is_digit.
  rewrite hp -!exprM -exprD; first smt().
  by [].
qed.

lemma independent_assignment_mass j f target :
  0<=j => coverage_assignment j f => size target=256 =>
  mu (dlist accepted_digest j) (fun ds => forall g, 0<=g<j =>
    group_event f g target (nth [] ds g))=(1%r/2%r)^(132+18*j).
proof.
  move=> hj hf ht; rewrite (dlistE [] accepted_digest (fun g d => group_event f g target d) j).
  rewrite (eq_big_seq _ (fun g => group_mass f g) (range 0 j)).
  + move=> g /mem_range hg /=; exact (coverage_group_mass f g target ht).
  exact (assignment_product_mass j f hj hf).
qed.
