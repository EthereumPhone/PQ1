(* Exact public-query traces for the actual chain loop, including cache hits.
   This is a deterministic history property, not a fresh-sampling premise. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import PersistentGrind AcceptedContexts LinearChain RawChainTrace RawWots.

op linear_queries (h : (raw_input,digest) fmap)
    (f : int -> raw_input -> raw_input) (value : raw_input) (indices : int list) =
  with indices = [] => []
  with indices = index :: rest =>
    f index value :: linear_queries h f (linear_step h f value index) rest.

lemma linear_queries_cat h f value prefix suffix :
  linear_queries h f value (prefix ++ suffix) =
    linear_queries h f value prefix ++
    linear_queries h f (linear_value h f value prefix) suffix.
proof.
  elim: prefix value => [value /= | index rest ih value /=].
  + by rewrite /linear_value /=.
  by rewrite /linear_value /= ih.
qed.

lemma linear_queries_rcons h f value indices index :
  linear_queries h f value (rcons indices index) =
    rcons (linear_queries h f value indices)
      (f index (linear_value h f value indices)).
proof. by rewrite -cats1 linear_queries_cat /= cats1. qed.

lemma linear_queries_extends h h' f value indices :
  extends h h' => linear_recorded h f value indices =>
  linear_queries h' f value indices=linear_queries h f value indices.
proof.
  move=> he; elim: indices value => [value /= | index rest ih value /=]; first trivial.
  move=> [hx hr].
  by rewrite (linear_step_extends h h' f value index he hx) (ih _ hr).
qed.

lemma linear_queries_range_member h f value start n x :
  0<=n => x \in linear_queries h f value (range start (start+n)) =>
  exists j, start<=j<start+n /\ x=f j (linear_value h f value (range start j)).
proof.
  move=> hn; elim: n hn => [|n hn ih].
  + by rewrite /= range_geq 1:// /=.
  rewrite (_ : start+(n+1)=(start+n)+1) 1:/# rangeSr 1:/#
    linear_queries_rcons mem_rcons.
  move=> [hx|hx].
  + exists (start+n); smt().
  have [j [hj he]] := ih hx; exists j; smt().
qed.

lemma hash_records_linear_queries f initial indices value0 trace0 queries0 x0 :
  hoare [Independent.hash :
    linear_recorded Independent.rawhistory f initial indices /\
    linear_value Independent.rawhistory f initial indices=value0 /\
    linear_queries Independent.rawhistory f initial indices=trace0 /\
    Independent.queries=queries0 /\ x=x0 ==>
    linear_recorded Independent.rawhistory f initial indices /\
    linear_value Independent.rawhistory f initial indices=value0 /\
    linear_queries Independent.rawhistory f initial indices=trace0 /\
    Independent.queries=rcons queries0 x0 /\ Independent.rawhistory.[x0]=Some res].
proof.
  proc; sp 1; if; auto;
    smt(linear_recorded_extends linear_queries_extends extends_insert get_set_sameE domE).
qed.

lemma raw_chain_exact_queries seed0 layer0 tree0 kp0 index0 initial start0 stop0 queries0 :
  hoare [RawWots(PreparationView(Independent)).chain :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=index0 /\
    current=initial /\ start=start0 /\ stop=stop0 /\ start0<=stop0 /\
    Independent.queries=queries0 ==>
    linear_recorded Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 stop0) /\
    res=linear_value Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 stop0) /\
    Independent.queries=queries0 ++
      linear_queries Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
        initial (range start0 stop0)].
proof.
  proc; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=index0 /\
    stop=stop0 /\ start0<=j<=stop0 /\
    linear_recorded Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 j) /\
    linear_value Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 j)=current /\
    Independent.queries=queries0 ++
      linear_queries Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
        initial (range start0 j)).
  + exists* j,current,
      (linear_queries Independent.rawhistory (chain_input seed0 layer0 tree0 kp0 index0)
        initial (range start0 j)); elim* => j0 current0 trace0.
    wp; call (hash_records_linear_queries (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 j0) current0 trace0 (queries0 ++ trace0)
      (chain_input seed0 layer0 tree0 kp0 index0 j0 current0)).
    auto; move=> &hr hp.
    split.
    + split; first smt().
      split; first smt().
      split; first smt().
      split; first smt().
      by rewrite /chain_input; smt().
    move=> _ d queries h [hrec [hval [htrace [hq hentry]]]].
    have hstep := linear_recorded_step h
      (chain_input seed0 layer0 tree0 kp0 index0)
      initial (range start0 j0) j0 d current0 hrec hval hentry.
    have hrange : range start0 (j{hr}+1)=rcons (range start0 j0) j0 by smt(rangeSr).
    rewrite hrange linear_queries_rcons hval htrace; smt(cat_rcons).
  auto; move=> &hr hp; split.
  + have hstart : start{hr}=start0 by smt().
    rewrite hstart range_geq 1:// /linear_value /= cats0; smt().
  smt().
qed.
