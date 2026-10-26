(* Every query in an actual chain prefix is its canonical supported input.
   Prefixes cover key generation and shuffled signing, including repeated keys. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import LinearChain LinearSplit RawChainTrace WotsReference.
require import AddressedLinearQueries AddressedWotsCanonicity.
require import AddressedWotsLog.

lemma canonical_wots_prefix_queries h s seed layer tree kp index stop :
  wots_address_valid layer tree kp index 0 => 0<=stop<=7 =>
  wots_key layer tree kp index \in s =>
  linear_recorded h (chain_input seed layer tree kp index)
    (wots_start s layer tree kp index) (range 0 stop) =>
  all (canonical_wots_input h s seed)
    (linear_queries h (chain_input seed layer tree kp index)
      (wots_start s layer tree kp index) (range 0 stop)).
proof.
  move=> hv hn hk hr; apply/allP => x hx.
  have [j [hj he]] := linear_queries_range_member h (chain_input seed layer tree kp index)
    (wots_start s layer tree kp index) 0 stop x _ hx; first smt().
  have [hp rest] := linear_range_split h (chain_input seed layer tree kp index)
    (wots_start s layer tree kp index) 0 j stop _ _ hr; first 2 smt().
  rewrite /canonical_wots_input; left; exists layer tree kp index j.
  rewrite /canonical_wots_chain_supported /canonical_wots_chain_input;
    move: hv; rewrite /wots_address_valid; smt().
qed.

lemma raw_chain_preserves_private_table s0 :
  hoare [RawWots(PreparationView(Independent)).chain :
    Independent.secrethistory=s0 ==> Independent.secrethistory=s0].
proof.
  proc; while (Independent.secrethistory=s0).
  + wp; inline *; sp; if; auto.
  auto.
qed.

lemma raw_chain_canonical_prefix_queries seed0 layer0 tree0 kp0 index0 stop0 s0 queries0 :
  hoare [RawWots(PreparationView(Independent)).chain :
    wots_address_valid layer0 tree0 kp0 index0 0 /\ 0<=stop0<=7 /\
    wots_key layer0 tree0 kp0 index0 \in s0 /\
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=index0 /\
    current=wots_start s0 layer0 tree0 kp0 index0 /\ start=0 /\ stop=stop0 /\
    Independent.queries=queries0 /\ Independent.secrethistory=s0 ==>
    Independent.secrethistory=s0 /\
    all (canonical_wots_input Independent.rawhistory Independent.secrethistory seed0)
      (drop (size queries0) Independent.queries) /\
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 queries0 Independent.queries].
proof.
  conseq (raw_chain_exact_queries seed0 layer0 tree0 kp0 index0
    (wots_start s0 layer0 tree0 kp0 index0) 0 stop0 queries0)
    (raw_chain_preserves_private_table s0).
  + smt().
  move=> &m hp result queries h [[hr [hout hqueries]] hs].
  have hv : wots_address_valid layer0 tree0 kp0 index0 0 by smt().
  have hn : 0<=stop0<=7 by smt().
  have hk : wots_key layer0 tree0 kp0 index0 \in s0 by smt().
  rewrite hs hqueries drop_size_cat; split; first trivial.
  have hall := canonical_wots_prefix_queries h s0 seed0 layer0 tree0 kp0 index0 stop0 hv hn hk hr.
  split; first exact hall.
  exists (linear_queries h (chain_input seed0 layer0 tree0 kp0 index0)
    (wots_start s0 layer0 tree0 kp0 index0) (range 0 stop0)); smt().
qed.

lemma raw_chain_extends_canonical_log seed0 layer0 tree0 kp0 index0 stop0 s0 base :
  hoare [RawWots(PreparationView(Independent)).chain :
    wots_address_valid layer0 tree0 kp0 index0 0 /\ 0<=stop0<=7 /\
    wots_key layer0 tree0 kp0 index0 \in s0 /\
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=index0 /\
    current=wots_start s0 layer0 tree0 kp0 index0 /\ start=0 /\ stop=stop0 /\
    Independent.secrethistory=s0 /\
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    Independent.secrethistory=s0 /\
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  exists* Independent.queries; elim* => queries0.
  conseq (raw_chain_canonical_prefix_queries seed0 layer0 tree0 kp0 index0 stop0 s0 queries0)
    (chain_keeps_canonical_wots_log seed0 base queries0).
  + smt().
  smt(canonical_wots_log_compose).
qed.
