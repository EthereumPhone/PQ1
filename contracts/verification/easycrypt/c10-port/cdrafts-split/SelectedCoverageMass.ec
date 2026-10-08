(* A fixed target and distinct witness positions carry the assignment charge. *)
require import AllCore List Distr DList RealSeries StdOrder.
require import C10RawOracle AcceptedDigestDistribution CoverageAssignment IidSelection.
import RField RealOrder.

op assignment_pool_event target witnesses f (nodes : digest list) =
  forall g, 0<=g<size witnesses =>
    group_event f g (nth [] nodes target) (nth [] nodes (nth 0 witnesses g)).
op ordered_assignment_event j f (nodes : digest list) =
  forall g, 0<=g<j => group_event f g (head [] nodes) (nth [] (behead nodes) g).

lemma ordered_assignment_mass j f : 0<=j => coverage_assignment j f =>
  mu (dlist accepted_digest (j+1)) (ordered_assignment_event j f)=(1%r/2%r)^(132+18*j).
proof.
  move=> hj hf; rewrite dlistS 1:hj /= dmap_dprodE dletE.
  have he : (fun d => mu1 accepted_digest d *
    mu (dmap (dlist accepted_digest j) (fun ds => d::ds)) (ordered_assignment_event j f)) =
    (fun d => mu1 accepted_digest d * (1%r/2%r)^(132+18*j)).
  + apply fun_ext => d; case (mu1 accepted_digest d=0%r)=> hz; first by rewrite hz.
    have hd : d \in accepted_digest by apply/supportP.
    have [hs _] := accepted_digest_support d hd.
    rewrite dmapE /ordered_assignment_event /(\o) /= (independent_assignment_mass j f d hj hf hs).
    by [].
  by rewrite he sumZr -weightE accepted_digest_ll /=.
qed.

lemma selected_assignment_mass n target witnesses f :
  0<=n => uniq (target::witnesses) =>
  all (fun i=>0<=i<n) (target::witnesses) => coverage_assignment (size witnesses) f =>
  mu (dlist accepted_digest n) (assignment_pool_event target witnesses f)=
    (1%r/2%r)^(132+18*size witnesses).
proof.
  move=> hn hu hb hf.
  have he := iid_distinct_selection [] accepted_digest n (target::witnesses) accepted_digest_ll hn hu hb.
  have hm : mu (dlist accepted_digest n) (assignment_pool_event target witnesses f)=
    mu (dmap (dlist accepted_digest n) (fun xs => map (nth [] xs) (target::witnesses)))
      (ordered_assignment_event (size witnesses) f).
  + rewrite dmapE; apply mu_eq=> nodes /=; rewrite /assignment_pool_event /ordered_assignment_event /(\o) /=.
    rewrite eq_iff; split=> h g hg; have hh := h g hg; move: hh;
      by rewrite (nth_map 0) //.
  rewrite hm he /= (: 1+size witnesses=size witnesses+1) 1:/#.
  exact (ordered_assignment_mass (size witnesses) f (size_ge0 witnesses) hf).
qed.
