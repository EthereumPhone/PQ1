(* Functional WOTS search under the explicit fixed-backend interpretation.
   Every queried prefix, cached value and call is retained, including exhaustion. *)
require import AllCore List FMap.
require import C10FirstHit C10FixedBackend C10SearchAcceptance.
require import C10Representation C10RawOracle C10RawGrind C10Bytes C10Counter KeygenPrefixes.

op functional_wots_query seed layer tree kp message i =
  wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) i.

op functional_wots_digests f seed layer tree kp message =
  mkseq (fun i => bits_to_bytes (f (functional_wots_query seed layer tree kp message i))) signing_budget.

op wots_rejected (f : raw_input -> digest) (q : int -> raw_input) n =
  forall j, 0 <= j < n => wots_sum (bits_to_bytes (f (q j))) <> wots_target.

op wots_prefix_result f q (result : (int * digest) option) i =
  (result = None /\ wots_rejected f q i) \/
  (0 < i /\ result = Some (i-1,f (q (i-1))) /\
    wots_sum (bits_to_bytes (f (q (i-1)))) = wots_target /\ wots_rejected f q (i-1)).

lemma backend_history_mkseqS f h q i : 0 <= i =>
  backend_history f h (mkseq q (i+1)) =
    remember (backend_history f h (mkseq q i)) (q i) (f (q i)).
proof. by move=> hi; rewrite mkseqS 1:hi backend_history_rcons. qed.

lemma functional_wots_prefix f h c seed0 layer0 tree0 kp0 message0 :
  hoare[PairedAcceptanceWots(PreparationView(FixedPrefix)).count :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ message = message0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ FixedBackend.calls = c ==>
    exists i, 0 <= i <= signing_budget /\
      FixedBackend.fn = f /\
      FixedBackend.history = backend_history f h
        (mkseq (functional_wots_query seed0 layer0 tree0 kp0 message0) i) /\
      backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+i /\
      wots_prefix_result f (functional_wots_query seed0 layer0 tree0 kp0 message0) res i /\
      (res = None => i = signing_budget)].
proof.
  proc; while (
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ message = message0 /\
    0 <= i <= signing_budget /\ FixedBackend.fn = f /\
    FixedBackend.history = backend_history f h
      (mkseq (functional_wots_query seed0 layer0 tree0 kp0 message0) i) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+i /\
    wots_prefix_result f (functional_wots_query seed0 layer0 tree0 kp0 message0) result i).
  + exists* i; elim* => i0; wp.
    call (fixed_hash f
      (backend_history f h (mkseq (functional_wots_query seed0 layer0 tree0 kp0 message0) i0))
      (functional_wots_query seed0 layer0 tree0 kp0 message0 i0) (c+i0)).
    auto => />; rewrite /functional_wots_query /wots_prefix_result /wots_rejected;
      smt(backend_history_mkseqS).
  auto => />; rewrite /wots_prefix_result /wots_rejected /signing_budget
    mkseq0 backend_history_nil; smt().
qed.

lemma fixed_wots_lossless :
  islossless PairedAcceptanceWots(PreparationView(FixedPrefix)).count.
proof.
  proc; while true (signing_budget-i).
  + move=> z; wp; call fixed_hash_ll; auto; smt().
  auto; smt().
qed.

lemma wots_prefix_finish f q result i :
  0 <= i <= signing_budget => wots_prefix_result f q result i =>
  (result = None => i = signing_budget) =>
  let slot = wots_first_slot (mkseq (fun j => bits_to_bytes (f (q j))) signing_budget) in
  i = (if slot = 0 then signing_budget else slot) /\
  result = (if slot = 0 then None else Some (slot-1,f (q (slot-1)))).
proof.
  move=> hi hp hd; rewrite wots_first_slot_common /=.
  case (result = None) => hn.
  + have hr : wots_rejected f q i by move: hp; rewrite /wots_prefix_result; smt().
    have he : i = signing_budget by smt().
    have hz := first_slot_mkseq_zero (fun d => wots_sum d = wots_target)
      (fun j => bits_to_bytes (f (q j))) signing_budget _.
    - move: hr; rewrite /wots_rejected; smt().
    by rewrite hz hn he.
  have [hip [hv [ha hr]]] :
    0 < i /\ result = Some (i-1,f (q (i-1))) /\
    wots_sum (bits_to_bytes (f (q (i-1)))) = wots_target /\
    wots_rejected f q (i-1) by move: hp; rewrite /wots_prefix_result; smt().
  have hs := first_slot_mkseq_hit (fun d => wots_sum d = wots_target)
    (fun j => bits_to_bytes (f (q j))) signing_budget (i-1) _ ha hr.
  + smt().
  rewrite hs /=; smt().
qed.

lemma fixed_wots_selector f h c seed0 layer0 tree0 kp0 message0 :
  hoare[PairedAcceptanceWots(PreparationView(FixedPrefix)).count :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ message = message0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ FixedBackend.calls = c ==>
    let slot = wots_first_slot (functional_wots_digests f seed0 layer0 tree0 kp0 message0) in
    let steps = if slot = 0 then signing_budget else slot in
    FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+steps /\
    FixedBackend.history = backend_history f h
      (mkseq (functional_wots_query seed0 layer0 tree0 kp0 message0) steps) /\
    res = (if slot = 0 then None else Some (slot-1,
      f (functional_wots_query seed0 layer0 tree0 kp0 message0 (slot-1))))].
proof.
  conseq (functional_wots_prefix f h c seed0 layer0 tree0 kp0 message0) => //.
  rewrite /functional_wots_digests; smt(wots_prefix_finish).
qed.
