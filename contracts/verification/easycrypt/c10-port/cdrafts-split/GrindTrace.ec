(* External Q2 research: a retained prefix of rejected trials and its first
   accepted digest, needed to distinguish repeated contexts from fresh draws. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains C10Counter PrefixGuess PrefixHybrid RoleGrind.
require import PersistentGrind AcceptedContexts.

op trial_random (s : (raw_input,digest) fmap) random message i =
  compact_r (oget s.[r_tail random message (U32.insubd i)]).
op trial_input (s : (raw_input,digest) fmap) random message seed root i =
  hmsg_input seed root (trial_random s random message i ++ nseq 16 0) message.
op trial_digest (s h : (raw_input,digest) fmap) random message seed root i =
  oget h.[trial_input s random message seed root i].
op trial_recorded (s h : (raw_input,digest) fmap) random message seed root i =
  r_tail random message (U32.insubd i) \in s /\
  trial_input s random message seed root i \in h.
op rejected_prefix (s h : (raw_input,digest) fmap) random message seed root n =
  forall i, 0 <= i < n =>
    trial_recorded s h random message seed root i /\
    !accept_digest (trial_digest s h random message seed root i).
op completed_trace (s h : (raw_input,digest) fmap) random message seed root (answer : raw_input * digest) =
  exists j, 0 <= j < signing_budget /\
    rejected_prefix s h random message seed root j /\
    trial_recorded s h random message seed root j /\
    accept_digest (trial_digest s h random message seed root j) /\
    answer = (trial_random s random message j,trial_digest s h random message seed root j).

lemma trial_extends s0 h0 s h random message seed root i :
  extends s0 s => extends h0 h =>
  trial_recorded s0 h0 random message seed root i =>
  trial_recorded s h random message seed root i /\
  trial_random s random message i = trial_random s0 random message i /\
  trial_digest s h random message seed root i = trial_digest s0 h0 random message seed root i.
proof.
  rewrite /extends /trial_recorded /trial_random /trial_input /trial_digest.
  smt(domE).
qed.

lemma rejected_prefix_extends s0 h0 s h random message seed root n :
  extends s0 s => extends h0 h =>
  rejected_prefix s0 h0 random message seed root n =>
  rejected_prefix s h random message seed root n.
proof. rewrite /rejected_prefix; smt(trial_extends). qed.

lemma completed_trace_extends s0 h0 s h random message seed root answer :
  extends s0 s => extends h0 h =>
  completed_trace s0 h0 random message seed root answer =>
  completed_trace s h random message seed root answer.
proof.
  move=> hs hh; rewrite /completed_trace => hex.
  elim hex => j [#] hj hbound hp ht ha he.
  exists j; smt(rejected_prefix_extends trial_extends).
qed.

lemma completed_trace_unique s h random message seed root a b :
  completed_trace s h random message seed root a =>
  completed_trace s h random message seed root b => a = b.
proof.
  rewrite /completed_trace /rejected_prefix.
  move=> hai hbj.
  elim hai => i [#] hi hib hp ht ha he.
  elim hbj => j [#] hj hjb hq hu hb hf.
  have hij : i = j by smt().
  smt().
qed.

lemma rejected_prefix_zero s h random message seed root :
  rejected_prefix s h random message seed root 0.
proof. rewrite /rejected_prefix; smt(). qed.

lemma rejected_prefix_step s h random message seed root i :
  rejected_prefix s h random message seed root i =>
  trial_recorded s h random message seed root i =>
  !accept_digest (trial_digest s h random message seed root i) =>
  rejected_prefix s h random message seed root (i+1).
proof. rewrite /rejected_prefix; smt(). qed.
