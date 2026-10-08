(* Every accepted H_msg table entry has a matching index in the iid sample pool. *)
require import AllCore List Distr DList FMap.
require import C10RawOracle C10RawGrind C10Randomizer PrefixGuess PrefixHybrid.
require import AcceptedDigestDistribution AcceptedPrefixSampling HmsgMemoOracle.

op accepted_records (h : (raw_input,digest) fmap) (keys : raw_input list) (nodes : digest list) =
  size keys=size nodes /\
  forall x d, size x=160 => accept_digest d => h.[x]=Some d =>
    exists i, 0<=i<size nodes /\ nth [] keys i=x /\ nth [] nodes i=d.

lemma accepted_records_empty : accepted_records empty [] [].
proof. by rewrite /accepted_records /=; smt(emptyE). qed.
lemma accepted_records_append h keys nodes x d :
  accepted_records h keys nodes =>
  accepted_records h.[x<-d] (rcons keys x) (rcons nodes d).
proof.
  move=> [hs hr]; split; first by rewrite !size_rcons hs.
  move=> z v hz hv he; case (z=x)=> hzx; last first.
  + have hg : h.[z]=Some v by smt(get_setE).
    have [i [hi [hk hn]]] := hr z v hz hv hg.
    exists i; rewrite !nth_rcons size_rcons; smt().
  have hd : d=v by smt(get_setE).
  exists (size nodes); rewrite !nth_rcons size_rcons hs /=; smt(size_ge0).
qed.
lemma accepted_records_skip h keys nodes x d :
  accepted_records h keys nodes => (size x<>160 \/ !accept_digest d) =>
  accepted_records h.[x<-d] keys nodes.
proof.
  move=> [hs hr] hx; split=> // z v hz hv.
  move=> hg; have hzx : z<>x by smt(get_setE).
  apply (hr z v hz hv); smt(get_setE).
qed.
lemma hmsg_hash_records :
  hoare[HmsgMemo(AcceptedSamples).hash :
    accepted_records HmsgMemo.rawhistory HmsgMemo.accepted_keys AcceptedSamples.nodes /\
    size AcceptedSamples.nodes<=HmsgMemo.accepted_calls ==>
    accepted_records HmsgMemo.rawhistory HmsgMemo.accepted_keys AcceptedSamples.nodes /\
    size AcceptedSamples.nodes<=HmsgMemo.accepted_calls].
proof.
  proc; sp 1; if; last by auto; smt().
  wp; if.
  + inline SplitAcceptedDigest(AcceptedSamples).sample AcceptedSamples.sample.
    sp 0; seq 1 : (accepted_records HmsgMemo.rawhistory HmsgMemo.accepted_keys AcceptedSamples.nodes /\
      size AcceptedSamples.nodes<=HmsgMemo.accepted_calls /\ size x=160 /\ x \notin HmsgMemo.rawhistory).
    - by auto.
    if; auto.
    + move=> &hr [[hr [hc [hx hn]]] _] d hd.
      have [_ ha] := accepted_digest_support d hd.
      rewrite /= hx ha get_set_sameE /= ha /= size_rcons.
      split; first exact (accepted_records_append _ _ _ _ _ hr).
      smt().
    move=> &hr [[hr [hc [hx hn]]] _] d hd.
    have [_ ha] := rejected_digest_support d hd.
    rewrite /= hx (: accept_digest d=false) 1:/# get_set_sameE /= (: accept_digest d=false) 1:/# /=.
    split=> //; apply accepted_records_skip => //; smt().
  auto; move=> &hr [[[qs [_ [hr hc]]] hn] hx] d hd.
  rewrite get_set_sameE /= (: size x{hr}<>160) 1:/# /=.
  split=> //; apply accepted_records_skip => //; smt().
qed.
lemma hmsg_derive_records :
  hoare[HmsgMemo(AcceptedSamples).derive :
    accepted_records HmsgMemo.rawhistory HmsgMemo.accepted_keys AcceptedSamples.nodes /\
    size AcceptedSamples.nodes<=HmsgMemo.accepted_calls ==>
    accepted_records HmsgMemo.rawhistory HmsgMemo.accepted_keys AcceptedSamples.nodes /\
    size AcceptedSamples.nodes<=HmsgMemo.accepted_calls].
proof. by proc; if; auto. qed.
lemma hmsg_context_records (A <: PrefixContext {-HmsgMemo,-AcceptedSamples}) :
  hoare[A(HmsgMemo(AcceptedSamples)).run :
    accepted_records HmsgMemo.rawhistory HmsgMemo.accepted_keys AcceptedSamples.nodes /\
    size AcceptedSamples.nodes<=HmsgMemo.accepted_calls ==>
    accepted_records HmsgMemo.rawhistory HmsgMemo.accepted_keys AcceptedSamples.nodes /\
    size AcceptedSamples.nodes<=HmsgMemo.accepted_calls].
proof.
  proc (accepted_records HmsgMemo.rawhistory HmsgMemo.accepted_keys AcceptedSamples.nodes /\
    size AcceptedSamples.nodes<=HmsgMemo.accepted_calls) => //.
  + exact hmsg_hash_records.
  exact hmsg_derive_records.
qed.
