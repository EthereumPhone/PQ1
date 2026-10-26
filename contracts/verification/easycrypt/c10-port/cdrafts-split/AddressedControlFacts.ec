(* Finite counterexamples supporting the control suite. These are raw byte
   inputs admitted by the public oracle, not invented honest-signer calls. *)
require import AllCore List FSet FMap.
require import C10RawOracle RawKeygen PrefixGuess NodeQueryDomain DomainNodeCollision.
require import AddressedNodeCollision AddressedBuckets AddressedBucketHistory AddressedMemoCount AddressedOrdinaryInputs.
require import AddressedForsException AddressedForsExceptionCount.

op control_key0 : raw_input = nseq 64 0.
op control_key1 : raw_input = rcons control_key0 0.
op control_key2 : raw_input = [1].
op control_digest : digest = nseq 256 false.
op control_memo = empty.[control_key0<-control_digest].[control_key1<-control_digest].
op control_exception = nseq 32 0 ++ address 0 0 3 12 0 0 0 ++ pad (nseq 16 0).

lemma control_exception_included : exceptional_fors_query control_exception.
proof.
  have h := exceptional_fors_leaf_query (nseq 32 0) 0 12 0 (nseq 16 0) _ _ _ _;
    first 4 smt(size_nseq).
  move: h; rewrite /control_exception; smt().
qed.

lemma control_two_exception_calls : exceptional_fors_count [control_exception;control_exception]=2.
proof. by rewrite /exceptional_fors_count /= control_exception_included /=. qed.

lemma control_keys :
  node_query control_key0 /\ node_query control_key1 /\
  control_key0<>control_key1 /\ addressed_label control_key0=addressed_label control_key1.
proof.
  have h0 : size control_key0=64 by rewrite /control_key0 size_nseq /=.
  have h1 : size control_key1=65 by rewrite /control_key1 size_rcons h0.
  have ht : take 64 control_key1=control_key0.
  + by rewrite /control_key1 -cats1 -{1}h0 take_size_cat.
  rewrite /addressed_label /node_query h0 h1 /=; smt(take_size).
qed.

lemma addressed_labels_empty : addressed_labels empty=fset0.
proof. by rewrite /addressed_labels fdom0 image0. qed.

lemma addressed_excess_singleton x d : addressed_excess empty.[x<-d]=0.
proof.
  have hf : x \notin empty<:raw_input,digest> by smt(mem_empty).
  have hi := addressed_excess_insert empty x d hf.
  move: hi; rewrite addressed_excess_empty addressed_labels_empty in_fset0 /=; smt().
qed.

lemma addressed_two_keys_excess x y dx dy :
  x<>y => addressed_label x=addressed_label y => addressed_excess empty.[x<-dx].[y<-dy]=1.
proof.
  move=> hd hl.
  have hf : y \notin empty.[x<-dx] by smt(mem_set mem_empty).
  rewrite (addressed_excess_insert empty.[x<-dx] y dy hf) addressed_excess_singleton.
  have hm : addressed_label y \in addressed_labels empty.[x<-dx].
  + rewrite /addressed_labels imageP; exists x; rewrite mem_fdom mem_set mem_empty; smt().
  by rewrite hm /=.
qed.

lemma control_distinct_same_label : addressed_excess control_memo=1.
proof. rewrite /control_memo; apply addressed_two_keys_excess; smt(control_keys). qed.

lemma control_cached_key : addressed_excess empty.[control_key0<-control_digest].[control_key0<-control_digest]=0.
proof. by rewrite set_set_sameE addressed_excess_singleton. qed.

lemma control_raw_prepopulation s seed : size seed=32 => 1<=nonordinary_count control_memo s seed.
proof.
  move=> hs; have h := addressed_excess_bound control_memo s seed hs.
  by move: h; rewrite control_distinct_same_label.
qed.

lemma control_collision_witness : addressed_node_collision control_memo.
proof.
  have [#] h0 h1 hd hl := control_keys.
  exists control_key0 control_key1 control_digest control_digest.
  rewrite /control_memo !get_setE; smt(addressed_label_node).
qed.

lemma control_first_sample_no_excess :
  !(1<=addressed_excess empty.[control_key0<-control_digest]).
proof. by rewrite addressed_excess_singleton. qed.

lemma control_different_address : addressed_label control_key0<>addressed_label control_key2.
proof.
  have h0 : size control_key0=64 by rewrite /control_key0 size_nseq /=.
  rewrite /addressed_label /node_query /control_key2 h0 /=.
  have ht : size (take 64 control_key0)=64 by rewrite -h0 take_size.
  smt().
qed.
