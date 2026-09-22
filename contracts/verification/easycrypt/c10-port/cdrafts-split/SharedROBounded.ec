(* A classical lazy random-oracle search, conditional on its entry history.
   Inputs may be selected after seeing that history. The exact IID lemma
   requires that this particular input list is unique and absent from history;
   the history-aware inequality below counts only initially unknown inputs;
   it does not infer freshness from a nonce or prove a SHA-256 refinement. *)
require import AllCore List Distr StdOrder.
require import BoundedIID.
import RField RealOrder.

op ro_search ['x 'y] (d : 'y distr) (p : 'y -> bool)
  (history : ('x * 'y) list) (inputs : 'x list) : 'y option distr =
  with inputs = [] => dunit None
  with inputs = x :: rest =>
    if assoc history x <> None then
      if p (oget (assoc history x)) then dunit (assoc history x)
      else ro_search d p history rest
    else dlet d (fun y => if p y then dunit (Some y)
      else ro_search d p ((x,y) :: history) rest).

lemma fresh_search_is_iid ['x 'y] (d : 'y distr) (p : 'y -> bool)
  (inputs : 'x list) :
  uniq inputs => forall (history : ('x * 'y) list),
    (forall x, x \in inputs => assoc history x = None) =>
    ro_search d p history inputs = bounded d p (map (fun _ => tt) inputs).
proof.
  elim: inputs => [|x xs ih] /=; first by [].
  move=> [hnot hu] history hf.
  rewrite hf 1:// /=; apply eq_dlet => // y.
  case (p y) => hp //=; apply ih => // z hz.
  have hn : z <> x by apply negP; move=> he; move: hz; rewrite he hnot.
  by rewrite assoc_cons hn /=; apply hf; right.
qed.

lemma fresh_search_exhaustion ['x 'y] (d : 'y distr) (p : 'y -> bool)
  (history : ('x * 'y) list) (inputs : 'x list) :
  is_lossless d => uniq inputs =>
  (forall x, x \in inputs => assoc history x = None) =>
  mu1 (ro_search d p history inputs) None = (1%r - mu d p) ^ size inputs.
proof.
  by move=> dll hu hf; rewrite fresh_search_is_iid // bounded_exhaustion // size_map.
qed.

(* An old failing answer is replayed, not sampled independently again. *)
lemma replay_failed_answer ['x 'y] (d : 'y distr) (p : 'y -> bool)
  (x : 'x) (y : 'y) : !p y =>
  ro_search d p [(x,y)] [x] = dunit None.
proof. by move=> hy; rewrite /ro_search /= hy. qed.

op fresh_count ['x 'y] (history : ('x * 'y) list) (inputs : 'x list) =
  count (fun x => assoc history x = None) inputs.

lemma fresh_count_insert ['x 'y] (history : ('x * 'y) list)
  (inputs : 'x list) (x : 'x) (y : 'y) :
  !(x \in inputs) => fresh_count ((x,y)::history) inputs = fresh_count history inputs.
proof.
  move=> hn; rewrite /fresh_count; apply eq_in_count => z hz.
  have hzx : z <> x by apply negP; move=> he; move: hz; rewrite he hn.
  by rewrite /= assoc_cons hzx.
qed.

(* History-aware tail bound. Known answers can only reduce the number of fresh
   trials; arbitrary known successes can make the search stop sooner. Thus no
   independence is assumed of the entry history or of its known answers. *)
lemma history_search_exhaustion ['x 'y] (d : 'y distr) (p : 'y -> bool)
  (inputs : 'x list) :
  is_lossless d => uniq inputs => forall (history : ('x * 'y) list),
  mu1 (ro_search d p history inputs) None <=
    (1%r - mu d p) ^ fresh_count history inputs.
proof.
  move=> dll; elim: inputs => [|x xs ih] /=.
  + by move=> history; rewrite /fresh_count /= dunit1E expr0.
  move=> [hn hu] history.
  case (assoc history x = None) => hx.
  + rewrite hx /= /fresh_count /= hx /= -/fresh_count.
    pose nf := fresh_count history xs.
    have nf0 : 0 <= nf by rewrite /nf /fresh_count; exact count_ge0.
    apply (ler_trans (mu1 (bounded d p (tt :: nseq nf tt)) None)).
    - rewrite /=; apply mu_dlet_le => y hy.
      case (p y) => hp; rewrite hp /=; first by [].
      have hh := ih hu ((x,y)::history).
      rewrite (fresh_count_insert history xs x y hn) in hh.
      by rewrite bounded_exhaustion 1:dll size_nseq IntOrder.ler_maxr 1:nf0 /nf.
    by rewrite bounded_exhaustion 1:dll /= size_nseq IntOrder.ler_maxr 1:nf0.
  rewrite /= /fresh_count /= hx /= -/fresh_count.
  case (p (oget (assoc history x))) => hp; rewrite ?hp /=.
  + have hsome : assoc history x <> None by exact hx.
    rewrite dunit1E /pred1 /= hsome /b2r /=.
    clear ih; apply expr_ge0; have := mu_bounded d p; smt().
  exact (ih hu history).
qed.
