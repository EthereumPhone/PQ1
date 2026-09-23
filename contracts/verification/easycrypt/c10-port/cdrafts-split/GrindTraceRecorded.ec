(* External Q2 research: the actual bounded loop records its first acceptance. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains C10Counter PrefixGuess PrefixHybrid RoleGrind.
require import PersistentGrind AcceptedContexts GrindTrace MonotoneHistory.

lemma derive_rejected random0 message0 seed0 root0 n tail0 :
  hoare[Independent.derive :
    rejected_prefix Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 n /\
    tail = tail0 ==>
    rejected_prefix Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 n /\
    Independent.secrethistory.[tail0] = Some res].
proof.
  proc; if; auto;
    smt(rejected_prefix_extends extends_refl extends_insert get_set_sameE domE).
qed.

lemma hash_rejected random0 message0 seed0 root0 n tail0 rd0 x0 :
  hoare[Independent.hash :
    rejected_prefix Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 n /\
    Independent.secrethistory.[tail0] = Some rd0 /\ x = x0 ==>
    rejected_prefix Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 n /\
    Independent.secrethistory.[tail0] = Some rd0 /\ Independent.rawhistory.[x0] = Some res].
proof.
  proc; sp 1; if; auto;
    smt(rejected_prefix_extends extends_refl extends_insert get_set_sameE domE).
qed.

lemma trial_value_recorded s h random message seed root i rd hd :
  s.[r_tail random message (U32.insubd i)] = Some rd =>
  h.[hmsg_input seed root (compact_r rd ++ nseq 16 0) message] = Some hd =>
  trial_recorded s h random message seed root i /\
  trial_random s random message i = compact_r rd /\
  trial_digest s h random message seed root i = hd.
proof.
  rewrite /trial_recorded /trial_random /trial_input /trial_digest; smt(domE).
qed.

lemma trace_recorded_step s h random message seed root i rd hd :
  0 <= i < signing_budget =>
  rejected_prefix s h random message seed root i =>
  s.[r_tail random message (U32.insubd i)] = Some rd =>
  h.[hmsg_input seed root (compact_r rd ++ nseq 16 0) message] = Some hd =>
  (!accept_digest hd => rejected_prefix s h random message seed root (i+1)) /\
  (accept_digest hd => completed_trace s h random message seed root (compact_r rd,hd)).
proof.
  move=> hi hp hs hh.
  have [#] ht hr hdv := trial_value_recorded s h random message seed root i rd hd hs hh.
  split.
  + smt(rejected_prefix_step).
  move=> ha; rewrite /completed_trace; exists i; smt().
qed.

lemma role_grind_records_trace random0 message0 seed0 root0 :
  hoare[RoleGrind(Independent).run :
    random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 ==>
    res <> None => completed_trace Independent.secrethistory Independent.rawhistory
      random0 message0 seed0 root0 (oget res)].
proof.
  proc; while (random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    0 <= i <= signing_budget /\
    (if result = None then
      rejected_prefix Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 i
     else completed_trace Independent.secrethistory Independent.rawhistory
       random0 message0 seed0 root0 (oget result))).
  + seq 2 : (random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
      0 <= i < signing_budget /\ result = None /\ r = compact_r rd /\
      rejected_prefix Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 i /\
      Independent.secrethistory.[r_tail random0 message0 (U32.insubd i)] = Some rd).
    - wp; exists* i; elim* => i0.
      call (derive_rejected random0 message0 seed0 root0 i0
        (r_tail random0 message0 (U32.insubd i0))); auto.
    wp; exists* i, rd, r; elim* => i0 rd0 r0.
    call (hash_rejected random0 message0 seed0 root0 i0
      (r_tail random0 message0 (U32.insubd i0)) rd0
      (hmsg_input seed0 root0 (r0 ++ nseq 16 0) message0)).
    auto; smt(trace_recorded_step).
  auto; rewrite /signing_budget; smt(rejected_prefix_zero).
qed.
