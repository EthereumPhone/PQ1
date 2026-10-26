(* Counts exceptional-address calls in the real FORS builder. A repeated
   memoized call is still counted; there is no assumed freshness budget. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import RawForsPathReplay AddressedForsException.

op exceptional_fors_count (queries : raw_input list) = size (filter exceptional_fors_query queries).

lemma exceptional_fors_count_rcons queries x :
  exceptional_fors_count (rcons queries x)=exceptional_fors_count queries+b2i (exceptional_fors_query x).
proof.
  rewrite /exceptional_fors_count filter_rcons; case (exceptional_fors_query x);
    rewrite /= /b2i; smt(size_rcons).
qed.

lemma exceptional_hash_count q flag :
  hoare [Independent.hash :
    exceptional_fors_count Independent.queries=q /\ exceptional_fors_query x=flag ==>
    exceptional_fors_count Independent.queries=q+b2i flag].
proof. proc; sp 1; if; auto; smt(exceptional_fors_count_rcons). qed.

lemma exceptional_hash_excluded q :
  hoare [Independent.hash :
    exceptional_fors_count Independent.queries=q /\ !exceptional_fors_query x ==>
    exceptional_fors_count Independent.queries=q].
proof. conseq (exceptional_hash_count q false); smt(b2i0). qed.

lemma exceptional_fors_derive q :
  hoare [PreparationView(Independent).fors : exceptional_fors_count Independent.queries=q ==>
    exceptional_fors_count Independent.queries=q].
proof. proc; inline Independent.derive; sp; if; auto. qed.

lemma exceptional_leaf_counter_step tree j :
  0<=j => b2i (tree=12 /\ 0<j)+b2i (tree=12 /\ j=0)=b2i (tree=12).
proof. rewrite /b2i; smt(). qed.

lemma raw_fors_tree_exception_count seed0 tree0 q0 :
  hoare [RawFors(PreparationView(Independent)).tree :
    seed=seed0 /\ tree=tree0 /\ size seed0=32 /\ 0<=tree0<13 /\
    exceptional_fors_count Independent.queries=q0 ==>
    exceptional_fors_count Independent.queries=q0+b2i (tree0=12)].
proof.
  proc; while (seed=seed0 /\ tree=tree0 /\ size seed0=32 /\ 0<=tree0<13 /\
    0<=j<=2048 /\ size stack<=j /\
    exceptional_fors_count Independent.queries=q0+b2i (tree0=12 /\ 0<j)).
  + wp; while (seed=seed0 /\ tree=tree0 /\ size seed0=32 /\ 0<=tree0<13 /\
      0<=j<2048 /\ 0<=height /\ height+size stack<=j /\
      exceptional_fors_count Independent.queries=q0+b2i (tree0=12)).
    - wp; call (exceptional_hash_excluded (q0+b2i (tree0=12))).
      auto; move=> &m hp.
      have hh : 1<=height{m}+1<4294967296 by smt(size_ge0).
      have he := exceptional_fors_parent_excluded seed{m} ht{m} tree{m}
        (height{m}+1) (j{m} %/ (2^(height{m}+1)))
        (head ([],0) stack{m}).`1 current{m} _ hh; first smt().
      rewrite /fors_pair in he.
      smt(size_behead size_ge0 size_eq0).
    exists* j; elim* => j0.
    wp; call (exceptional_hash_count (q0+b2i (tree0=12 /\ 0<j0)) (tree0=12 /\ j0=0)).
    wp; call (exceptional_fors_derive (q0+b2i (tree0=12 /\ 0<j0))).
    auto; smt(exceptional_fors_leaf_query node_width exceptional_leaf_counter_step size_ge0).
  auto; smt(size_rcons size_ge0 b2i0).
qed.

lemma raw_fors_root_exception_count seed0 tree0 q0 :
  hoare [RawFors(PreparationView(Independent)).root :
    seed=seed0 /\ tree=tree0 /\ size seed0=32 /\ 0<=tree0<13 /\
    exceptional_fors_count Independent.queries=q0 ==>
    exceptional_fors_count Independent.queries=q0+b2i (tree0=12)].
proof. proc; call (raw_fors_tree_exception_count seed0 tree0 q0); auto. qed.
