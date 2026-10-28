(* Every accepted count-query table entry has a matching index in the iid sample pool. *)
require import AllCore List Distr DList FMap.
require import C10RawOracle RawWots C10RawGrind C10Randomizer PrefixGuess PrefixHybrid.
require import WotsAcceptedDistribution WotsAcceptedPrefix WotsCountDomain WotsMemoOracle.

op wots_accepted_records (h : (raw_input,digest) fmap) (keys : raw_input list) (nodes : digest list) =
  size keys=size nodes /\
  forall x d, wots_count_query x => count_accepts d => h.[x]=Some d =>
    exists i, 0<=i<size nodes /\ nth [] keys i=x /\ nth [] nodes i=d.

lemma wots_accepted_records_empty : wots_accepted_records empty [] [].
proof. by rewrite /wots_accepted_records /=; smt(emptyE). qed.
lemma wots_accepted_records_append h keys nodes x d :
  wots_accepted_records h keys nodes =>
  wots_accepted_records h.[x<-d] (rcons keys x) (rcons nodes d).
proof.
  move=> [hs hr]; split; first by rewrite !size_rcons hs.
  move=> z v hz hv he; case (z=x)=> hzx; last first.
  + have hg : h.[z]=Some v by smt(get_setE).
    have [i [hi [hk hn]]] := hr z v hz hv hg.
    exists i; rewrite !nth_rcons size_rcons; smt().
  have hd : d=v by smt(get_setE).
  exists (size nodes); rewrite !nth_rcons size_rcons hs /=; smt(size_ge0).
qed.
lemma wots_accepted_records_skip h keys nodes x d :
  wots_accepted_records h keys nodes => (!wots_count_query x \/ !count_accepts d) =>
  wots_accepted_records h.[x<-d] keys nodes.
proof.
  move=> [hs hr] hx; split=> // z v hz hv.
  move=> hg; have hzx : z<>x by smt(get_setE).
  apply (hr z v hz hv); smt(get_setE).
qed.
lemma wots_hash_records :
  hoare[WotsMemo(WotsAcceptedSamples).hash :
    wots_accepted_records WotsMemo.rawhistory WotsMemo.accepted_keys WotsAcceptedSamples.nodes /\
    size WotsAcceptedSamples.nodes<=WotsMemo.accepted_calls ==>
    wots_accepted_records WotsMemo.rawhistory WotsMemo.accepted_keys WotsAcceptedSamples.nodes /\
    size WotsAcceptedSamples.nodes<=WotsMemo.accepted_calls].
proof.
  proc; sp 1; if; last by auto; smt().
  wp; if.
  + inline SplitWotsAcceptedDigest(WotsAcceptedSamples).sample WotsAcceptedSamples.sample.
    sp 0; seq 1 : (wots_accepted_records WotsMemo.rawhistory WotsMemo.accepted_keys WotsAcceptedSamples.nodes /\
      size WotsAcceptedSamples.nodes<=WotsMemo.accepted_calls /\ wots_count_query x /\ x \notin WotsMemo.rawhistory).
    - by auto.
    if; auto.
    + move=> &hr [[hr [hc [hx hn]]] _] d hd.
      have [_ ha] := accepted_wots_digest_support d hd.
      rewrite /= hx ha get_set_sameE /= ha /= size_rcons.
      split; first exact (wots_accepted_records_append _ _ _ _ _ hr).
      smt().
    move=> &hr [[hr [hc [hx hn]]] _] d hd.
    have [_ ha] := rejected_wots_digest_support d hd.
    rewrite /= hx (: count_accepts d=false) 1:/# get_set_sameE /= (: count_accepts d=false) 1:/# /=.
    split=> //; apply wots_accepted_records_skip => //; smt().
  auto; move=> &hr [[[qs [_ [hr hc]]] hn] hx] d hd.
  rewrite get_set_sameE /= (: !wots_count_query x{hr}) 1:/# /=.
  split=> //; apply wots_accepted_records_skip => //; smt().
qed.
lemma wots_derive_records :
  hoare[WotsMemo(WotsAcceptedSamples).derive :
    wots_accepted_records WotsMemo.rawhistory WotsMemo.accepted_keys WotsAcceptedSamples.nodes /\
    size WotsAcceptedSamples.nodes<=WotsMemo.accepted_calls ==>
    wots_accepted_records WotsMemo.rawhistory WotsMemo.accepted_keys WotsAcceptedSamples.nodes /\
    size WotsAcceptedSamples.nodes<=WotsMemo.accepted_calls].
proof. by proc; if; auto. qed.
lemma wots_context_records (A <: PrefixContext {-WotsMemo,-WotsAcceptedSamples}) :
  hoare[A(WotsMemo(WotsAcceptedSamples)).run :
    wots_accepted_records WotsMemo.rawhistory WotsMemo.accepted_keys WotsAcceptedSamples.nodes /\
    size WotsAcceptedSamples.nodes<=WotsMemo.accepted_calls ==>
    wots_accepted_records WotsMemo.rawhistory WotsMemo.accepted_keys WotsAcceptedSamples.nodes /\
    size WotsAcceptedSamples.nodes<=WotsMemo.accepted_calls].
proof.
  proc (wots_accepted_records WotsMemo.rawhistory WotsMemo.accepted_keys WotsAcceptedSamples.nodes /\
    size WotsAcceptedSamples.nodes<=WotsMemo.accepted_calls) => //.
  + exact wots_hash_records.
  exact wots_derive_records.
qed.
