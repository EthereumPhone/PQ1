(* Any adaptive prefix of accepted fresh draws is dominated by a fixed iid pool
   for extension-closed events. The client cannot inspect the sampler's state. *)
require import AllCore List Distr DList Xreal StdOrder.
require import C10RawOracle AcceptedDigestDistribution.

module type AcceptedSampler = { proc sample() : digest }.
module type AcceptedClient (S : AcceptedSampler) = { proc run() : unit { S.sample } }.
module AcceptedSamples = {
  var nodes : digest list
  proc init() : unit = { nodes <- []; }
  proc sample() : digest = {
    var d;
    d <$ accepted_digest;
    nodes <- rcons nodes d;
    return d;
  }
}.
module AcceptedGame (A : AcceptedClient) = {
  proc run() : unit = { AcceptedSamples.init(); A(AcceptedSamples).run(); }
}.
op accepted_completion q (p : digest list -> bool) nodes =
  if size nodes<=q then
    Ep (dlist accepted_digest (q-size nodes)) (fun more => (p (nodes++more))%xr)
  else 0%xr.
op extension_closed (p : digest list -> bool) =
  forall xs ys, p xs => p (xs++ys).

lemma accepted_completion_step q p nodes :
  Ep accepted_digest (fun d => accepted_completion q p (rcons nodes d)) <=
    accepted_completion q p nodes.
proof.
  case (size nodes<q) => hn.
  + rewrite /accepted_completion (: size nodes<=q) 1:/# /=.
    rewrite (eq_Ep _ _ (fun d =>
      Ep (dlist accepted_digest (q-size nodes-1)) (fun more => (p (rcons nodes d++more))%xr))).
    - by move=> d _ /=; rewrite size_rcons (: size nodes+1<=q) 1:/# /=; congr; smt().
    rewrite (: q-size nodes=(q-size nodes-1)+1) 1:/# dlistS 1:/# /=
      dmap_dprodE Ep_dlet.
    apply le_Ep => d _ /=; rewrite Ep_dmap.
    apply le_Ep => more _ /=; by rewrite -cats1 -catA /=.
  rewrite /accepted_completion (eq_Ep _ _ (fun _ => 0%xr)).
  + by move=> d _ /=; rewrite size_rcons (: !(size nodes+1<=q)) 1:/#.
  rewrite EpC /=; apply xle0x.
qed.

lemma accepted_completion_dominates q p nodes : extension_closed p =>
  (size nodes<=q /\ p nodes)%xr <= accepted_completion q p nodes.
proof.
  move=> hp; case (size nodes<=q /\ p nodes) => hc; last by rewrite /=; apply xle0x.
  rewrite /= /accepted_completion (: size nodes<=q) 1:/# /=.
  have he : Ep (dlist accepted_digest (q-size nodes)) (fun _ => 1%xr)=1%xr.
  + by rewrite EpC (dlist_ll accepted_digest _ accepted_digest_ll) /=.
  rewrite -{1}he; apply le_Ep => more _ /=.
  have hm : p (nodes++more) by move: hp; rewrite /extension_closed; smt().
  by rewrite hm /=.
qed.

ehoare accepted_client_completion (A <: AcceptedClient {-AcceptedSamples}) q p :
  A(AcceptedSamples).run : accepted_completion q p AcceptedSamples.nodes ==>
    accepted_completion q p AcceptedSamples.nodes.
proof.
  proc (accepted_completion q p AcceptedSamples.nodes); first 2 by auto.
  proc; auto => &hr; exact (accepted_completion_step q p AcceptedSamples.nodes{hr}).
qed.

lemma accepted_adaptive_completion (A <: AcceptedClient {-AcceptedSamples}) q p :
  0<=q => extension_closed p =>
  ehoare [AcceptedGame(A).run : (mu (dlist accepted_digest q) p)%xr ==>
    (size AcceptedSamples.nodes<=q /\ p AcceptedSamples.nodes)%xr].
proof.
  move=> hq hp; proc.
  conseq (_ : _ ==> accepted_completion q p AcceptedSamples.nodes).
  + move=> &hr; apply xle_cxr_l.
    - by move=> nodes; apply accepted_completion_dominates.
    by [].
  + move=> &hr; apply xle_cxr_r => h; exact (h AcceptedSamples.nodes{hr}).
  call (accepted_client_completion A q p).
  by inline AcceptedSamples.init; auto; rewrite /accepted_completion /= hq /= Ep_mu.
qed.

lemma accepted_adaptive_prefix (A <: AcceptedClient {-AcceptedSamples}) q p &m :
  0<=q => extension_closed p =>
  Pr[AcceptedGame(A).run() @ &m : size AcceptedSamples.nodes<=q /\ p AcceptedSamples.nodes]
    <= mu (dlist accepted_digest q) p.
proof.
  move=> hq hp; have hn := mu_bounded (dlist accepted_digest q) p.
  by byehoare (accepted_adaptive_completion A q p hq hp) => //.
qed.
