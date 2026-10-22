(* Two-query bounded FORS search under one deterministic backend and one
   retained history. Both caller-supplied OptRand encodings use this result. *)
require import AllCore List FMap.
require import C10FirstHit C10FixedBackend C10SearchAcceptance.
require import C10Representation C10RawOracle C10RawGrind C10Bytes C10Counter.

op functional_r_query key random message i = key ++ r_preimage [] random message i.
op functional_randomizer f key random message i =
  compact_r (f (functional_r_query key random message i)).
op functional_fors_query f key random message seed root i =
  hmsg_preimage seed root (pad_node (functional_randomizer f key random message i)) message.
op functional_fors_digests f key random message seed root =
  mkseq (fun i => bits_to_bytes (f (functional_fors_query f key random message seed root i))) signing_budget.
op functional_fors_queries f key random message seed root n =
  flatten (mkseq (fun i => [functional_r_query key random message i;
    functional_fors_query f key random message seed root i]) n).
op functional_fors_history f h key random message seed root n =
  backend_history f h (functional_fors_queries f key random message seed root n).

op fors_rejected (f : raw_input -> digest) (q : int -> raw_input) n =
  forall j, 0 <= j < n => fors_zero_field (bits_to_bytes (f (q j))) <> 0.
op fors_prefix_result f q (r : int -> raw_input) (result : (raw_input * digest) option) i =
  (result = None /\ fors_rejected f q i) \/
  (0 < i /\ result = Some (r (i-1),f (q (i-1))) /\
    fors_zero_field (bits_to_bytes (f (q (i-1)))) = 0 /\ fors_rejected f q (i-1)).

lemma functional_fors_history_zero f h key random message seed root :
  functional_fors_history f h key random message seed root 0 = h.
proof. by rewrite /functional_fors_history /functional_fors_queries mkseq0 /= backend_history_nil. qed.

lemma functional_fors_history_step f h key random message seed root i : 0 <= i =>
  functional_fors_history f h key random message seed root (i+1) =
    remember (remember (functional_fors_history f h key random message seed root i)
      (functional_r_query key random message i) (f (functional_r_query key random message i)))
      (functional_fors_query f key random message seed root i)
      (f (functional_fors_query f key random message seed root i)).
proof.
  move=> hi; rewrite /functional_fors_history /functional_fors_queries
    mkseqS 1:hi flatten_rcons /backend_history foldl_cat /=.
  by trivial.
qed.

lemma fixed_fors_prefix f h c key0 random0 message0 seed0 root0 :
  hoare[PairedAcceptanceGrind(FixedPrefix).run :
    random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ FixedBackend.calls = c ==>
    exists i, 0 <= i <= signing_budget /\
      FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
      FixedBackend.history = functional_fors_history f h key0 random0 message0 seed0 root0 i /\
      backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+2*i /\
      fors_prefix_result f (functional_fors_query f key0 random0 message0 seed0 root0)
        (functional_randomizer f key0 random0 message0) res i /\
      (res = None => i = signing_budget)].
proof.
  proc; while (
    random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    0 <= i <= signing_budget /\ FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = functional_fors_history f h key0 random0 message0 seed0 root0 i /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+2*i /\
    fors_prefix_result f (functional_fors_query f key0 random0 message0 seed0 root0)
      (functional_randomizer f key0 random0 message0) result i).
  + exists* i; elim* => i0; wp.
    call (fixed_hash f
      (remember (functional_fors_history f h key0 random0 message0 seed0 root0 i0)
        (functional_r_query key0 random0 message0 i0) (f (functional_r_query key0 random0 message0 i0)))
      (functional_fors_query f key0 random0 message0 seed0 root0 i0) (c+2*i0+1)).
    wp; call (fixed_derive f (functional_fors_history f h key0 random0 message0 seed0 root0 i0)
      (r_preimage [] random0 message0 i0) (c+2*i0) key0).
    auto => />; rewrite /functional_r_query /functional_fors_query /functional_randomizer
      /fors_prefix_result /fors_rejected; smt(functional_fors_history_step).
  auto => />; rewrite /fors_prefix_result /fors_rejected /signing_budget
    functional_fors_history_zero; smt().
qed.

lemma fixed_fors_lossless : islossless PairedAcceptanceGrind(FixedPrefix).run.
proof.
  proc; while true (signing_budget-i).
  + move=> z; wp; call fixed_hash_ll; wp; call fixed_derive_ll; auto; smt().
  auto; smt().
qed.

lemma fors_prefix_finish f q r result i :
  0 <= i <= signing_budget => fors_prefix_result f q r result i =>
  (result = None => i = signing_budget) =>
  let slot = fors_first_slot (mkseq (fun j => bits_to_bytes (f (q j))) signing_budget) in
  i = (if slot = 0 then signing_budget else slot) /\
  result = (if slot = 0 then None else Some (r (slot-1),f (q (slot-1)))).
proof.
  move=> hi hp hd; rewrite fors_first_slot_common /=.
  case (result = None) => hn.
  + have hr : fors_rejected f q i by move: hp; rewrite /fors_prefix_result; smt().
    have he : i = signing_budget by smt().
    have hz := first_slot_mkseq_zero (fun d => fors_zero_field d = 0)
      (fun j => bits_to_bytes (f (q j))) signing_budget _.
    - move: hr; rewrite /fors_rejected; smt().
    by rewrite hz hn he.
  have [hip [hv [ha hr]]] :
    0 < i /\ result = Some (r (i-1),f (q (i-1))) /\
    fors_zero_field (bits_to_bytes (f (q (i-1)))) = 0 /\
    fors_rejected f q (i-1) by move: hp; rewrite /fors_prefix_result; smt().
  have hs := first_slot_mkseq_hit (fun d => fors_zero_field d = 0)
    (fun j => bits_to_bytes (f (q j))) signing_budget (i-1) _ ha hr.
  + smt().
  rewrite hs /=; smt().
qed.

lemma fixed_fors_selector f h c key0 random0 message0 seed0 root0 :
  hoare[PairedAcceptanceGrind(FixedPrefix).run :
    random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ FixedBackend.calls = c ==>
    let slot = fors_first_slot (functional_fors_digests f key0 random0 message0 seed0 root0) in
    let steps = if slot = 0 then signing_budget else slot in
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+2*steps /\
    FixedBackend.history = functional_fors_history f h key0 random0 message0 seed0 root0 steps /\
    res = (if slot = 0 then None else Some (functional_randomizer f key0 random0 message0 (slot-1),
      f (functional_fors_query f key0 random0 message0 seed0 root0 (slot-1))))].
proof.
  conseq (fixed_fors_prefix f h c key0 random0 message0 seed0 root0) => //.
  rewrite /functional_fors_digests; smt(fors_prefix_finish).
qed.
