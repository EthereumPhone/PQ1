(* Materialization reads already recorded private nodes. This helper alone
   grants no release authority; its caller decides whether to return them. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest.
require import ForsPrivateLeaves ForsLeafView WrapperForestMemo WrapperForsPlan.

module WrapperForestRelease (F : ForsLeafOracle) = {
  proc values(ht : int, digest : digest, finalnode : raw_input) : raw_input list = {
    var t, secret, secrets;
    t <- 0; secrets <- [];
    while (t < 12) {
      secret <@ F.secret(ht,t,forest_index digest t);
      secrets <- rcons secrets secret; t <- t+1;
    }
    return rcons secrets finalnode;
  }
}.

lemma wrapper_forest_release_ll (F <: ForsLeafOracle) :
  islossless F.secret => islossless WrapperForestRelease(F).values.
proof.
  move=> hf; proc; while true (12-t).
  + move=> z; wp; call hf; auto; smt().
  auto; smt().
qed.

lemma wrapper_fors_cached_secret s_ref ht_ref tree_ref target_ref sd_ref :
  hoare [ConcreteForsLeaf(PreparationView(Independent)).secret :
    Independent.secrethistory=s_ref /\ arg=(ht_ref,tree_ref,target_ref) /\
    s_ref.[fors_private_key ht_ref tree_ref target_ref]=Some sd_ref ==>
    Independent.secrethistory=s_ref /\ res=node sd_ref].
proof.
  proc; inline PreparationView(Independent).fors; wp.
  call (RawChainCached.derive_existing_entry s_ref (fors_private_key ht_ref tree_ref target_ref) sd_ref).
  auto; rewrite /fors_private_key; smt().
qed.

lemma wrapper_forest_release_recorded ht_ref digest_ref secrets_ref s_ref :
  hoare [WrapperForestRelease(ConcreteForsLeaf(PreparationView(Independent))).values :
    wrapper_fors_memo_prefix s_ref ht_ref digest_ref secrets_ref (range 0 12) /\
    ht=ht_ref /\ digest=digest_ref /\ finalnode=nth (nseq 16 0) secrets_ref 12 /\
    Independent.secrethistory=s_ref ==>
    Independent.secrethistory=s_ref /\ res=secrets_ref].
proof.
  case (wrapper_fors_memo_prefix s_ref ht_ref digest_ref secrets_ref (range 0 12)) => hm;
    last by conseq (_ : true ==> true); auto.
  proc.
  while (ht=ht_ref /\ digest=digest_ref /\ finalnode=nth (nseq 16 0) secrets_ref 12 /\
    Independent.secrethistory=s_ref /\ 0<=t<=12 /\ secrets=take t secrets_ref).
  + exists* t; elim* => t_ref.
    have hw : size secrets_ref=13 by move: hm; rewrite /wrapper_fors_memo_prefix; smt().
    have he : 0<=t_ref<12 => exists sd,
      s_ref.[fors_private_key ht_ref t_ref (forest_index digest_ref t_ref)]=Some sd /\
      nth (nseq 16 0) secrets_ref t_ref=node sd
      by move: hm; rewrite /wrapper_fors_memo_prefix; smt(mem_range).
    wp; call (_ : Independent.secrethistory=s_ref /\
      arg=(ht_ref,t_ref,forest_index digest_ref t_ref) /\ 0<=t_ref<12 ==>
      Independent.secrethistory=s_ref /\ res=nth (nseq 16 0) secrets_ref t_ref).
    - case (0<=t_ref<12) => ht.
      * have [sd [hs hv]] := he ht.
        conseq (wrapper_fors_cached_secret s_ref ht_ref t_ref (forest_index digest_ref t_ref) sd); smt().
      by conseq (_ : false ==> true); auto.
    auto => />; move=> h0 h1 h2.
    split; first by split; smt().
    rewrite (take_nth (nseq 16 0) t_ref secrets_ref); smt().
  auto; move: hm; rewrite /wrapper_fors_memo_prefix; smt(take0 take_nth take_size).
qed.

lemma wrapper_forest_release_total ht_ref digest_ref secrets_ref s_ref h_ref q_ref :
  phoare [WrapperForestRelease(ConcreteForsLeaf(PreparationView(Independent))).values :
    wrapper_fors_memo_prefix s_ref ht_ref digest_ref secrets_ref (range 0 12) /\
    ht=ht_ref /\ digest=digest_ref /\ finalnode=nth (nseq 16 0) secrets_ref 12 /\
    Independent.secrethistory=s_ref /\ Independent.rawhistory=h_ref /\ Independent.queries=q_ref ==>
    Independent.secrethistory=s_ref /\ Independent.rawhistory=h_ref /\ Independent.queries=q_ref /\
    res=secrets_ref] = 1%r.
proof.
  conseq (_ : true ==> true)
    (wrapper_forest_release_recorded ht_ref digest_ref secrets_ref s_ref); first 2 smt().
  apply (wrapper_forest_release_ll (ConcreteForsLeaf(PreparationView(Independent)))).
  proc; call BuilderTotality.preparation_fors_ll; auto.
qed.
