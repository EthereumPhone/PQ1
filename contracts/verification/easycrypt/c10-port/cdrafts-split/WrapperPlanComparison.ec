(* Internal equality can compare the public plans: equal randomizers identify
   the same recorded digest, which identifies all twelve stable private nodes. *)
require import AllCore List FMap.
require import C10RawOracle C10HashDomains PrefixGuess KeygenPrefixes RawKeygen RawForest RawSigner.
require import PersistentGrind AcceptedContexts SignerTrace ForestReferenceHistory.
require import WrapperForestMemo WrapperSigningPlan WrapperPlanSigner.

lemma wrapper_fors_memo_unique s ht digest secrets secrets' :
  wrapper_fors_memo_prefix s ht digest secrets (range 0 12) =>
  wrapper_fors_memo_prefix s ht digest secrets' (range 0 12) =>
  nth (nseq 16 0) secrets 12=nth (nseq 16 0) secrets' 12 => secrets=secrets'.
proof.
  move=> [hw ha] [hw' hb] hl.
  apply (eq_from_nth (nseq 16 0)); first smt().
  move=> i hi; case (i=12) => he; first smt().
  have [a [ha1 ha2]] := ha i _; first smt(mem_range).
  have [b [hb1 hb2]] := hb i _; first smt(mem_range).
  smt().
qed.

op wrapper_plan_equal (a b : wrapper_signature_plan) =
  (a.`1,a.`3,a.`4,a.`5)=(b.`1,b.`3,b.`4,b.`5).

lemma wrapper_planned_comparison h s seed root message sig_a sig_b plan_a plan_b :
  wrapper_plan_entry h seed root message plan_a => wrapper_plan_entry h seed root message plan_b =>
  wrapper_planned_signature s sig_a plan_a => wrapper_planned_signature s sig_b plan_b =>
  (sig_a=sig_b)=wrapper_plan_equal plan_a plan_b.
proof.
  move=> ha hb hsa hsb.
  have hf : sig_a=sig_b => wrapper_plan_equal plan_a plan_b.
  + move=> he; move: hsa hsb; rewrite /wrapper_planned_signature /wrapper_plan_equal; smt().
  suff hr : wrapper_plan_equal plan_a plan_b => sig_a=sig_b by smt().
  move=> he.
  have hd : plan_a.`2=plan_b.`2 by move: ha hb he; rewrite /wrapper_plan_entry /wrapper_plan_equal; smt().
  have hse : sig_a.`2=sig_b.`2.
  + apply (wrapper_fors_memo_unique s (hypertree_index plan_a.`2) plan_a.`2).
    - move: hsa; rewrite /wrapper_planned_signature; smt().
    - move: hsb; rewrite /wrapper_planned_signature; smt().
    move: hsa hsb he; rewrite /wrapper_planned_signature /wrapper_plan_equal; smt().
  move: hsa hsb he; rewrite /wrapper_planned_signature /wrapper_plan_equal; smt().
qed.

lemma wrapper_supported_comparison h s seed root message sig_a sig_b plan_a plan_b :
  wrapper_plan_supported h s seed root message sig_a plan_a =>
  wrapper_plan_supported h s seed root message sig_b plan_b => sig_a<>None =>
  (sig_b<>None /\ sig_a=sig_b)=
    (plan_b<>None /\ wrapper_plan_equal (oget plan_a) (oget plan_b)).
proof.
  move=> ha hb hsa; case (sig_b=None) => hsb.
  + move: ha hb; rewrite /wrapper_plan_supported /wrapper_planned_result; smt().
  have he := wrapper_planned_comparison h s seed root message
    (oget sig_a) (oget sig_b) (oget plan_a) (oget plan_b).
  move: ha hb he; rewrite /wrapper_plan_supported /wrapper_planned_result; smt().
qed.

lemma wrapper_plan_supported_extends h h' s s' seed root message signed planned :
  extends h h' => extends s s' => wrapper_plan_supported h s seed root message signed planned =>
  wrapper_plan_supported h' s' seed root message signed planned.
proof.
  move=> hh hs; rewrite /wrapper_plan_supported /wrapper_planned_result /wrapper_planned_signature /wrapper_plan_entry.
  move: hh; rewrite /extends; smt(wrapper_fors_memo_extends).
qed.

lemma wrapper_signer_plan_preserved (S <: CompleteSigner {-Independent}) seed0 root0 message0 signed0 planned0 :
  hoare [S(Independent).sign :
    wrapper_plan_supported Independent.rawhistory Independent.secrethistory seed0 root0 message0 signed0 planned0 ==>
    wrapper_plan_supported Independent.rawhistory Independent.secrethistory seed0 root0 message0 signed0 planned0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (complete_signer_histories S s0 h0); smt(extends_refl wrapper_plan_supported_extends).
qed.
