(* Selected ordinary FORS values remain in the private memo table. This
   invariant records availability, not external release of those values. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawForest ForsPrivateLeaves PersistentGrind.
require import PrefixGuess PrefixHybrid KeygenPrefixes RawFors ForsComponentHistory MonotoneHistory AcceptedContexts.

op wrapper_fors_memo_prefix s ht digest (secrets : raw_input list) visited =
  size secrets=13 /\ forall t, mem visited t => exists sd,
    s.[fors_private_key ht t (forest_index digest t)]=Some sd /\
    nth (nseq 16 0) secrets t=node sd.

lemma wrapper_fors_memo_extends s s' ht digest secrets visited :
  extends s s' => wrapper_fors_memo_prefix s ht digest secrets visited =>
  wrapper_fors_memo_prefix s' ht digest secrets visited.
proof. rewrite /extends /wrapper_fors_memo_prefix; smt(). qed.

lemma wrapper_fors_memo_empty s ht digest :
  wrapper_fors_memo_prefix s ht digest (nseq 13 (nseq 16 0)) [].
proof. rewrite /wrapper_fors_memo_prefix; smt(size_nseq). qed.

lemma wrapper_fors_memo_step s ht digest secrets visited t secret :
  0<=t<12 => wrapper_fors_memo_prefix s ht digest secrets visited =>
  (exists sd, s.[fors_private_key ht t (forest_index digest t)]=Some sd /\ secret=node sd) =>
  wrapper_fors_memo_prefix s ht digest (put secrets t secret) (rcons visited t).
proof.
  rewrite /wrapper_fors_memo_prefix; move=> hi [hs hp] [sd [he hv]].
  split; first smt(size_put).
  move=> j hj; case (j=t) => hjt.
  + exists sd; smt(nth_put mem_rcons).
  have [d [hd hn]] : exists d,
    s.[fors_private_key ht j (forest_index digest j)]=Some d /\
    nth (nseq 16 0) secrets j=node d by apply hp; smt(mem_rcons).
  exists d; smt(nth_put).
qed.

lemma wrapper_fors_memo_complete s ht digest secrets order :
  perm_eq order (range 0 12) =>
  wrapper_fors_memo_prefix s ht digest secrets order =>
  wrapper_fors_memo_prefix s ht digest secrets (range 0 12).
proof. rewrite /wrapper_fors_memo_prefix; smt(perm_eq_mem). qed.

lemma wrapper_fors_memo_last s ht digest secrets finalnode :
  wrapper_fors_memo_prefix s ht digest secrets (range 0 12) =>
  wrapper_fors_memo_prefix s ht digest (put secrets 12 finalnode) (range 0 12).
proof. rewrite /wrapper_fors_memo_prefix; smt(size_put nth_put mem_range). qed.

lemma wrapper_fors_one_keeps_memo ht0 digest0 secrets0 visited :
  hoare [RawForest(PreparationView(Independent)).one :
    wrapper_fors_memo_prefix Independent.secrethistory ht0 digest0 secrets0 visited ==>
    wrapper_fors_memo_prefix Independent.secrethistory ht0 digest0 secrets0 visited].
proof.
  exists* Independent.secrethistory,Independent.rawhistory; elim* => s0 h0.
  conseq (fors_one_extends RawForest s0 h0); smt(extends_refl wrapper_fors_memo_extends).
qed.

lemma wrapper_fors_root_keeps_memo ht0 digest0 secrets0 visited :
  hoare [RawFors(PreparationView(Independent)).root :
    wrapper_fors_memo_prefix Independent.secrethistory ht0 digest0 secrets0 visited ==>
    wrapper_fors_memo_prefix Independent.secrethistory ht0 digest0 secrets0 visited].
proof.
  exists* Independent.secrethistory,Independent.rawhistory; elim* => s0 h0.
  conseq (fors_root_extends RawFors s0 h0); smt(extends_refl wrapper_fors_memo_extends).
qed.
