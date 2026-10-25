(* Ordinary secrets are not returned by this forest planning interface.
   It retains the special thirteenth root-as-secret, paths and public root.
   Actual signer outputs can be reconstructed from the private memo table. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest RawShuffle.
require import ForsPrivateLeaves ForsLeafView ForestCoordinates RawShufflePermutation.
require import WrapperPrivateSchedule WrapperMemoProjection WrapperForsPlan WrapperForsOneProjection WrapperForestMemo.

module WrapperForestPlan (O : PreparationOracle) (F : ForsLeafOracle) = {
  proc sign(seed : raw_input, ht : int, digest : digest, shuffle : raw_input) : raw_input * raw_input list list * raw_input = {
    var subseed, order, step, t, planned, last, d, auths, roots;
    auths <- nseq 12 (nseq 11 (nseq 16 0)); roots <- nseq 13 (nseq 16 0);
    subseed <@ RawShuffle(O).derive(shuffle,[102;111;114;115]);
    order <@ RawShuffle(O).permutation(subseed,12);
    step <- 0;
    while (step < 12) {
      t <- nth 0 order step;
      planned <@ WrapperForsPublicPlan(F).one(seed,ht,t,forest_index digest t);
      auths <- put auths t planned.`2;
      roots <- put roots t planned.`1; step <- step+1;
    }
    last <@ LeafFors(F).root(seed,ht,12);
    d <@ O.hash(seed ++ address 0 ht 3 12 0 0 0 ++ pad last);
    roots <- put roots 12 (node d);
    d <@ O.hash(seed ++ address 0 ht 4 0 0 0 0 ++ flatten (map pad roots));
    return (last,auths,node d);
  }
}.

module type WrapperShuffle (O : PrefixOracle) = {
  proc permutation(seed : raw_input, n : int) : int list { O.hash }
}.
module WrapperConcreteShuffle (O : PrefixOracle) = {
  proc permutation = RawShuffle(PreparationView(O)).permutation
}.

lemma wrapper_shuffle_table_projection (S <: WrapperShuffle {-Independent}) :
  equiv [S(Independent).permutation ~ S(Independent).permutation :
    ={arg,glob S,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,glob S,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc (={Independent.rawhistory,Independent.secrethistory}) => //.
  exact wrapper_memo_hash_projection.
qed.

lemma wrapper_shuffle_derive_projection :
  equiv [RawShuffle(PreparationView(Independent)).derive ~ RawShuffle(PreparationView(Independent)).derive :
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof. proc; sp 1 1; if; auto; wp; call wrapper_memo_hash_projection; auto. qed.

lemma wrapper_fors_root_table_projection :
  equiv [RawFors(PreparationView(Independent)).root ~ LeafFors(ConcreteForsLeaf(PreparationView(Independent))).root :
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof.
  transitivity RawFors(PreparationView(Independent)).root
    (={arg,Independent.rawhistory,Independent.secrethistory} ==>
      ={res,Independent.rawhistory,Independent.secrethistory})
    (={arg,glob Independent} ==> ={res,glob Independent}) => //.
  + smt().
  + proc; call (wrapper_fors_tree_table_projection WrapperConcreteForsTree); auto.
  exact (leaf_fors_root_projection (PreparationView(Independent))).
qed.

lemma wrapper_forest_public_plan seed_ref ht_ref digest_ref :
  equiv [RawForest(PreparationView(Independent)).sign ~
    WrapperForestPlan(PreparationView(Independent),ConcreteForsLeaf(PreparationView(Independent))).sign :
    seed{1}=seed_ref /\ ht{1}=ht_ref /\ digest{1}=digest_ref /\
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    res{1}.`2=res{2}.`2 /\ res{1}.`3=res{2}.`3 /\
    nth (nseq 16 0) res{1}.`1 12=res{2}.`1 /\
    wrapper_fors_memo_prefix Independent.secrethistory{1} ht_ref digest_ref res{1}.`1 (range 0 12)].
proof.
  proc; seq 7 6 : (seed{1}=seed_ref /\ ht{1}=ht_ref /\ digest{1}=digest_ref /\
    ={seed,ht,digest,auths,roots,Independent.rawhistory,Independent.secrethistory} /\
    wrapper_fors_memo_prefix Independent.secrethistory{1} ht_ref digest_ref secrets{1} (range 0 12)).
  + while (seed{1}=seed_ref /\ ht{1}=ht_ref /\ digest{1}=digest_ref /\
      ={seed,ht,digest,order,step,auths,roots,Independent.rawhistory,Independent.secrethistory} /\
      0<=step{1}<=12 /\ perm_eq order{1} (range 0 12) /\
      wrapper_fors_memo_prefix Independent.secrethistory{1} ht_ref digest_ref secrets{1} (take step{1} order{1})).
    - exists* order{1},step{1},secrets{1}; elim* => ord st se.
      wp; call (_ : arg{1}=(seed_ref,ht_ref,nth 0 ord st,forest_index digest_ref (nth 0 ord st)) /\
        ={arg,Independent.rawhistory,Independent.secrethistory} /\
        wrapper_fors_memo_prefix Independent.secrethistory{1} ht_ref digest_ref se (take st ord) ==>
        ={Independent.rawhistory,Independent.secrethistory} /\ res{1}.`2=res{2}.`2 /\ res{1}.`3=res{2}.`1 /\
        wrapper_fors_memo_prefix Independent.secrethistory{1} ht_ref digest_ref se (take st ord) /\
        exists sd, Independent.secrethistory{1}.[fors_private_key ht_ref (nth 0 ord st)
          (forest_index digest_ref (nth 0 ord st))]=Some sd /\ res{1}.`1=node sd).
      * conseq (wrapper_fors_one_public_plan seed_ref ht_ref (nth 0 ord st)
          (forest_index digest_ref (nth 0 ord st)) (forest_index_range digest_ref (nth 0 ord st)))
          (wrapper_fors_one_keeps_memo ht_ref digest_ref se (take st ord)); smt(domE).
      auto; smt(wrapper_fors_memo_step take_nth perm_eq_size size_range mem_nth perm_eq_mem mem_range).
    wp; call (_ : ={arg,Independent.rawhistory,Independent.secrethistory} /\ n{1}=12 ==>
      ={res,Independent.rawhistory,Independent.secrethistory} /\ perm_eq res{1} (range 0 12)).
    - conseq (wrapper_shuffle_table_projection WrapperConcreteShuffle)
        (raw_shuffle_permutation (PreparationView(Independent)) 12 independent_hash_ll); smt().
    call wrapper_shuffle_derive_projection.
    auto; smt(wrapper_fors_memo_empty wrapper_fors_memo_complete take0 take_size perm_eq_size size_range).
  exists* secrets{1}; elim* => se.
  seq 1 1 : (seed{1}=seed_ref /\ ht{1}=ht_ref /\ digest{1}=digest_ref /\
    ={seed,ht,digest,auths,roots,last,Independent.rawhistory,Independent.secrethistory} /\ secrets{1}=se /\
    wrapper_fors_memo_prefix Independent.secrethistory{1} ht_ref digest_ref se (range 0 12)).
  + call (_ : ={arg,Independent.rawhistory,Independent.secrethistory} /\
      wrapper_fors_memo_prefix Independent.secrethistory{1} ht_ref digest_ref se (range 0 12) ==>
      ={res,Independent.rawhistory,Independent.secrethistory} /\
      wrapper_fors_memo_prefix Independent.secrethistory{1} ht_ref digest_ref se (range 0 12)).
    - conseq wrapper_fors_root_table_projection
        (wrapper_fors_root_keeps_memo ht_ref digest_ref se (range 0 12)); smt().
    auto.
  wp; call wrapper_memo_hash_projection; wp; call wrapper_memo_hash_projection.
  auto; rewrite /wrapper_fors_memo_prefix; smt(nth_put size_put mem_range).
qed.
