(* Any adaptive prefix of fresh full-digest draws is dominated by a fixed iid pool
   for extension-closed events. The client cannot inspect the sampler's state. *)
require import AllCore List Distr DList Xreal StdOrder.
require import C10RawOracle C10Randomizer AcceptedPrefixSampling.

module type FullDigestSampler = { proc sample() : digest }.
module type FullDigestClient (S : FullDigestSampler) = { proc run() : unit { S.sample } }.
module FullDigestSamples = {
  var nodes : digest list
  proc init() : unit = { nodes <- []; }
  proc sample() : digest = {
    var d;
    d <$ full_digest;
    nodes <- rcons nodes d;
    return d;
  }
}.
module FullDigestGame (A : FullDigestClient) = {
  proc run() : unit = { FullDigestSamples.init(); A(FullDigestSamples).run(); }
}.
op full_digest_completion q (p : digest list -> bool) nodes =
  if size nodes<=q then
    Ep (dlist full_digest (q-size nodes)) (fun more => (p (nodes++more))%xr)
  else 0%xr.

lemma full_digest_completion_step q p nodes :
  Ep full_digest (fun d => full_digest_completion q p (rcons nodes d)) <=
    full_digest_completion q p nodes.
proof.
  case (size nodes<q) => hn.
  + rewrite /full_digest_completion (: size nodes<=q) 1:/# /=.
    rewrite (eq_Ep _ _ (fun d =>
      Ep (dlist full_digest (q-size nodes-1)) (fun more => (p (rcons nodes d++more))%xr))).
    - by move=> d _ /=; rewrite size_rcons (: size nodes+1<=q) 1:/# /=; congr; smt().
    rewrite (: q-size nodes=(q-size nodes-1)+1) 1:/# dlistS 1:/# /=
      dmap_dprodE Ep_dlet.
    apply le_Ep => d _ /=; rewrite Ep_dmap.
    apply le_Ep => more _ /=; by rewrite -cats1 -catA /=.
  rewrite /full_digest_completion (eq_Ep _ _ (fun _ => 0%xr)).
  + by move=> d _ /=; rewrite size_rcons (: !(size nodes+1<=q)) 1:/#.
  rewrite EpC /=; apply xle0x.
qed.

lemma full_digest_completion_dominates q p nodes : extension_closed p =>
  (size nodes<=q /\ p nodes)%xr <= full_digest_completion q p nodes.
proof.
  move=> hp; case (size nodes<=q /\ p nodes) => hc; last by rewrite /=; apply xle0x.
  rewrite /= /full_digest_completion (: size nodes<=q) 1:/# /=.
  have he : Ep (dlist full_digest (q-size nodes)) (fun _ => 1%xr)=1%xr.
  + by rewrite EpC (dlist_ll full_digest _ full_digest_ll) /=.
  rewrite -{1}he; apply le_Ep => more _ /=.
  have hm : p (nodes++more) by move: hp; rewrite /extension_closed; smt().
  by rewrite hm /=.
qed.

ehoare full_digest_client_completion (A <: FullDigestClient {-FullDigestSamples}) q p :
  A(FullDigestSamples).run : full_digest_completion q p FullDigestSamples.nodes ==>
    full_digest_completion q p FullDigestSamples.nodes.
proof.
  proc (full_digest_completion q p FullDigestSamples.nodes); first 2 by auto.
  proc; auto => &hr; exact (full_digest_completion_step q p FullDigestSamples.nodes{hr}).
qed.

lemma full_digest_adaptive_completion (A <: FullDigestClient {-FullDigestSamples}) q p :
  0<=q => extension_closed p =>
  ehoare [FullDigestGame(A).run : (mu (dlist full_digest q) p)%xr ==>
    (size FullDigestSamples.nodes<=q /\ p FullDigestSamples.nodes)%xr].
proof.
  move=> hq hp; proc.
  conseq (_ : _ ==> full_digest_completion q p FullDigestSamples.nodes).
  + move=> &hr; apply xle_cxr_l.
    - by move=> nodes; apply full_digest_completion_dominates.
    by [].
  + move=> &hr; apply xle_cxr_r => h; exact (h FullDigestSamples.nodes{hr}).
  call (full_digest_client_completion A q p).
  by inline FullDigestSamples.init; auto; rewrite /full_digest_completion /= hq /= Ep_mu.
qed.

lemma full_digest_adaptive_prefix (A <: FullDigestClient {-FullDigestSamples}) q p &m :
  0<=q => extension_closed p =>
  Pr[FullDigestGame(A).run() @ &m : size FullDigestSamples.nodes<=q /\ p FullDigestSamples.nodes]
    <= mu (dlist full_digest q) p.
proof.
  move=> hq hp; have hn := mu_bounded (dlist full_digest q) p.
  by byehoare (full_digest_adaptive_completion A q p hq hp) => //.
qed.
