(* Any adaptive prefix of accepted fresh draws is dominated by a fixed iid pool
   for extension-closed events. The client cannot inspect the sampler's state. *)
require import AllCore List Distr DList Xreal StdOrder.
require import C10RawOracle WotsAcceptedDistribution WotsAcceptedPool AcceptedEncodingPool.


module type WotsAcceptedSampler = { proc sample() : digest }.
module type WotsAcceptedClient (S : WotsAcceptedSampler) = { proc run() : unit { S.sample } }.
module WotsAcceptedSamples = {
  var nodes : digest list
  proc init() : unit = { nodes <- []; }
  proc sample() : digest = {
    var d;
    d <$ accepted_wots_digest;
    nodes <- rcons nodes d;
    return d;
  }
}.
module WotsAcceptedGame (A : WotsAcceptedClient) = {
  proc run() : unit = { WotsAcceptedSamples.init(); A(WotsAcceptedSamples).run(); }
}.
op wots_completion q (p : digest list -> bool) nodes =
  if size nodes<=q then
    Ep (dlist accepted_wots_digest (q-size nodes)) (fun more => (p (nodes++more))%xr)
  else 0%xr.
op wots_extension_closed (p : digest list -> bool) =
  forall xs ys, p xs => p (xs++ys).

lemma wots_completion_step q p nodes :
  Ep accepted_wots_digest (fun d => wots_completion q p (rcons nodes d)) <=
    wots_completion q p nodes.
proof.
  case (size nodes<q) => hn.
  + rewrite /wots_completion (: size nodes<=q) 1:/# /=.
    rewrite (eq_Ep _ _ (fun d =>
      Ep (dlist accepted_wots_digest (q-size nodes-1)) (fun more => (p (rcons nodes d++more))%xr))).
    - by move=> d _ /=; rewrite size_rcons (: size nodes+1<=q) 1:/# /=; congr; smt().
    rewrite (: q-size nodes=(q-size nodes-1)+1) 1:/# dlistS 1:/# /=
      dmap_dprodE Ep_dlet.
    apply le_Ep => d _ /=; rewrite Ep_dmap.
    apply le_Ep => more _ /=; by rewrite -cats1 -catA /=.
  rewrite /wots_completion (eq_Ep _ _ (fun _ => 0%xr)).
  + by move=> d _ /=; rewrite size_rcons (: !(size nodes+1<=q)) 1:/#.
  rewrite EpC /=; apply xle0x.
qed.

lemma wots_completion_dominates q p nodes : wots_extension_closed p =>
  (size nodes<=q /\ p nodes)%xr <= wots_completion q p nodes.
proof.
  move=> hp; case (size nodes<=q /\ p nodes) => hc; last by rewrite /=; apply xle0x.
  rewrite /= /wots_completion (: size nodes<=q) 1:/# /=.
  have he : Ep (dlist accepted_wots_digest (q-size nodes)) (fun _ => 1%xr)=1%xr.
  + by rewrite EpC (dlist_ll accepted_wots_digest _ accepted_wots_digest_ll) /=.
  rewrite -{1}he; apply le_Ep => more _ /=.
  have hm : p (nodes++more) by move: hp; rewrite /wots_extension_closed; smt().
  by rewrite hm /=.
qed.

ehoare wots_accepted_client_completion (A <: WotsAcceptedClient {-WotsAcceptedSamples}) q p :
  A(WotsAcceptedSamples).run : wots_completion q p WotsAcceptedSamples.nodes ==>
    wots_completion q p WotsAcceptedSamples.nodes.
proof.
  proc (wots_completion q p WotsAcceptedSamples.nodes); first 2 by auto.
  proc; auto => &hr; exact (wots_completion_step q p WotsAcceptedSamples.nodes{hr}).
qed.

lemma wots_accepted_adaptive_completion (A <: WotsAcceptedClient {-WotsAcceptedSamples}) q p :
  0<=q => wots_extension_closed p =>
  ehoare [WotsAcceptedGame(A).run : (mu (dlist accepted_wots_digest q) p)%xr ==>
    (size WotsAcceptedSamples.nodes<=q /\ p WotsAcceptedSamples.nodes)%xr].
proof.
  move=> hq hp; proc.
  conseq (_ : _ ==> wots_completion q p WotsAcceptedSamples.nodes).
  + move=> &hr; apply xle_cxr_l.
    - by move=> nodes; apply wots_completion_dominates.
    by [].
  + move=> &hr; apply xle_cxr_r => h; exact (h WotsAcceptedSamples.nodes{hr}).
  call (wots_accepted_client_completion A q p).
  by inline WotsAcceptedSamples.init; auto; rewrite /wots_completion /= hq /= Ep_mu.
qed.

lemma wots_accepted_adaptive_prefix (A <: WotsAcceptedClient {-WotsAcceptedSamples}) q p &m :
  0<=q => wots_extension_closed p =>
  Pr[WotsAcceptedGame(A).run() @ &m : size WotsAcceptedSamples.nodes<=q /\ p WotsAcceptedSamples.nodes]
    <= mu (dlist accepted_wots_digest q) p.
proof.
  move=> hq hp; have hn := mu_bounded (dlist accepted_wots_digest q) p.
  by byehoare (wots_accepted_adaptive_completion A q p hq hp) => //.
qed.

lemma wots_adaptive_conditional_encoding_bound (A <: WotsAcceptedClient {-WotsAcceptedSamples}) q &m :
  0<=q => Pr[WotsAcceptedGame(A).run() @ &m :
    size WotsAcceptedSamples.nodes<=q /\ accepted_encoding_pool_collision WotsAcceptedSamples.nodes]
    <= conditional_encoding_charge q.
proof.
  move=> hq.
  have hp : wots_extension_closed accepted_encoding_pool_collision.
  + rewrite /wots_extension_closed /accepted_encoding_pool_collision => xs ys hn.
    rewrite accepted_encoding_words_cat cat_uniq; smt().
  have h := wots_accepted_adaptive_prefix A q accepted_encoding_pool_collision &m hq hp.
  have hi := iid_conditional_encoding_bound q hq; smt().
qed.
