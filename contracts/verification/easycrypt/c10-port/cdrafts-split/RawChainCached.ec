(* Replaying recorded raw chain calls is deterministic and leaves both tables unchanged. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import LinearChain LinearSplit RawChainTrace WotsReference WotsChainSplit ChainReferenceEntries ChainValueView.

lemma recorded_linear_next h f initial start stop j :
  start<=j<stop => linear_recorded h f initial (range start stop) =>
  exists d, h.[f j (linear_value h f initial (range start j))]=Some d /\
    linear_value h f initial (range start (j+1))=node d.
proof.
  move=> hj hr.
  have [hp [hs hv]] := linear_range_split h f initial start j stop _ _ hr; first 2 smt().
  have hm : f j (linear_value h f initial (range start j)) \in h
    by move: hs; rewrite (range_ltn j stop) 1:/# /=; smt().
  exists (oget h.[f j (linear_value h f initial (range start j))]); split; first smt(domE).
  by rewrite rangeSr 1:/# linear_value_rcons /linear_step.
qed.
lemma hash_existing_entry h0 x0 d :
  hoare [Independent.hash : Independent.rawhistory=h0 /\ x=x0 /\ h0.[x0]=Some d ==>
    Independent.rawhistory=h0 /\ res=d].
proof. proc; sp 1; if; auto; smt(domE). qed.
lemma derive_existing_entry s0 x0 d :
  hoare [Independent.derive : Independent.secrethistory=s0 /\ tail=x0 /\ s0.[x0]=Some d ==>
    Independent.secrethistory=s0 /\ res=d].
proof. proc; if; auto; smt(domE). qed.

lemma raw_chain_tables_replay seed0 layer0 tree0 kp0 i0 initial start0 stop0 h0 :
  hoare [RawWots(PreparationView(Independent)).chain :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=i0 /\
    current=initial /\ start=start0 /\ stop=stop0 /\ start0<=stop0 /\
    Independent.rawhistory=h0 /\
    linear_recorded h0 (chain_input seed0 layer0 tree0 kp0 i0) initial (range start0 stop0) ==>
    Independent.rawhistory=h0 /\
    res=linear_value h0 (chain_input seed0 layer0 tree0 kp0 i0) initial (range start0 stop0)].
proof.
  proc; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=i0 /\ stop=stop0 /\
    start0<=j<=stop0 /\ Independent.rawhistory=h0 /\
    linear_recorded h0 (chain_input seed0 layer0 tree0 kp0 i0) initial (range start0 stop0) /\
    current=linear_value h0 (chain_input seed0 layer0 tree0 kp0 i0) initial (range start0 j)).
  + exists* j; elim* => j0; wp.
    call (hash_existing_entry h0
      (chain_input seed0 layer0 tree0 kp0 i0 j0
        (linear_value h0 (chain_input seed0 layer0 tree0 kp0 i0) initial (range start0 j0)))
      (oget h0.[chain_input seed0 layer0 tree0 kp0 i0 j0
        (linear_value h0 (chain_input seed0 layer0 tree0 kp0 i0) initial (range start0 j0))])).
    auto; rewrite /chain_input; smt(recorded_linear_next).
  auto; move=> &m hp; split.
  + have hstart : start{m}=start0 by smt().
    rewrite hstart (range_geq start0 start0) 1:// /linear_value /=; smt().
  smt().
qed.

lemma concrete_chain_tables_replay seed0 layer0 tree0 kp0 i0 stop0 h0 s0 :
  0<=stop0<=7 =>
  hoare [ConcreteChain(Independent).value :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=i0 /\ stop=stop0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    chain_reference h0 s0 seed0 layer0 tree0 kp0 i0 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    res=wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 stop0].
proof.
  move=> hstop; proc.
  call (raw_chain_tables_replay seed0 layer0 tree0 kp0 i0 (wots_start s0 layer0 tree0 kp0 i0) 0 stop0 h0).
  inline PreparationView(Independent).wots; wp.
  call (derive_existing_entry s0 (wots_key layer0 tree0 kp0 i0) (oget s0.[wots_key layer0 tree0 kp0 i0])).
  auto; rewrite /chain_reference /wots_key /wots_start /wots_partial;
    smt(domE linear_range_split).
qed.
