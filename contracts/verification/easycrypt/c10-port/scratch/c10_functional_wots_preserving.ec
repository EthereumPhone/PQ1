require import AllCore List C10Representation IntDiv FMap C10RawOracle C10Bytes C10Counter C10RawGrind RawWots RoleGrind PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen C10AcceptanceBridge C10CallerInputBridge ShuffleBytes.

(* Finite first-hit selectors: zero is exhaustion; otherwise index + 1.
   A mathematical digest schedule does not perform additional oracle queries. *)


op first_slot ['a] (accept : 'a -> bool) (xs : 'a list) : int =
  foldr (fun x slot => if accept x then 1 else if slot = 0 then 0 else slot + 1) 0 xs.

























(* Paired acceptance inside actual bounded searches. The existing Shared
   oracle supplies 256-bit outputs under its valid-history invariant. Results,
   history and counters are preserved; no pure-SHA/oracle identification. *)

















module PairedAcceptanceWots (O : PreparationOracle) = {
  proc count(seed : raw_input, layer tree kp : int, message : raw_input) : (int * digest) option = {
    var i, d, result;
    i <- 0; result <- None;
    while (i < signing_budget /\ result = None) {
      d <@ O.hash(wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) i);
      if (wots_sum (bits_to_bytes d) = wots_target) { result <- Some (i,d); }
      i <- i+(2-1);
    }
    return result;
  }
  proc chain = CommonInputWots(O).chain
  proc recover(seed : raw_input, layer tree kp : int, message : raw_input, sigma : raw_input list, count : int) : raw_input = {
    var d, result, i, current, elements;
    d <@ O.hash(wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) count);
    result <- nseq 16 0;
    if (wots_sum (bits_to_bytes d) = wots_target) {
      i <- 0; elements <- [];
      while (i < 43) {
        current <@ chain(seed,layer,tree,kp,i,nth (nseq 16 0) sigma i,RadixEncoding.digit 3 d i,7);
        elements <- rcons elements current; i <- i+1;
      }
      d <@ O.hash(multi_preimage seed (address_words layer tree 1 kp 0 0 0) elements);
      result <- node d;
    }
    return result;
  }
}.

module PairedAcceptanceGrind (O : PrefixOracle) = {
  proc run(random message seed root : int list) : (int list * bool list) option = {
    var i, rd, hd, r, result;
    i <- 0; result <- None;
    while (i < signing_budget /\ result = None) {
      rd <@ O.derive(r_preimage [] random message i);
      r <- compact_r rd;
      hd <@ O.hash(hmsg_preimage seed root (pad_node r) message);
      if (fors_zero_field (bits_to_bytes hd) = 0) { result <- Some (r,hd); }
      i <- i+1;
    }
    return result;
  }
}.



















(* Deterministic functional interpretation, separate from the random oracle.
   Arbitrary prior history is retained and must agree with the same backend.
   This is not a claim about concrete SHA security or a RO simulation. *)


op backend_consistent (h : (raw_input,digest) fmap) (f : raw_input -> digest) =
  forall x y, h.[x] = Some y => y = f x.

op remember (h : (raw_input,digest) fmap) x y =
  if x \in h then h else h.[x <- y].

op backend_history (f : raw_input -> digest) h (queries : raw_input list) =
  foldl (fun table x => remember table x (f x)) h queries.













module FixedBackend = {
  var fn : raw_input -> digest
  var history : (raw_input,digest) fmap
  var calls : int

  proc init(f : raw_input -> digest) : unit = {
    fn <- f; history <- empty; calls <- 0;
  }
  proc hash(x : raw_input) : digest = {
    calls <- calls + 1;
    if (x \notin history) { history.[x] <- fn x; }
    return oget history.[x];
  }
}.

module FixedPrefix = {
  var key : raw_input
  proc hash = FixedBackend.hash
  proc derive(tail : raw_input) : digest = {
    var y; y <@ FixedBackend.hash(key ++ tail); return y;
  }
}.











(* Functional WOTS search under the explicit fixed-backend interpretation.
   Every queried prefix, cached value and call is retained, including exhaustion. *)




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











require C10SearchAcceptance.
lemma checked :
  equiv[PairedAcceptanceWots(PreparationView(FixedPrefix)).count ~ C10SearchAcceptance.PairedAcceptanceWots(PreparationView(FixedPrefix)).count :
    ={arg,glob FixedPrefix} ==> ={res,glob FixedPrefix}].
proof. proc; while (={seed,layer,tree,kp,message,i,result,glob FixedPrefix}).
  + wp; call (_ : ={arg,glob FixedPrefix} ==> ={res,glob FixedPrefix}); first by sim.
    auto => />; try ring.
  auto => />; try ring.
qed.

lemma first_slot_nil ['a] (p : 'a -> bool) : first_slot p [] = 0.
proof. by rewrite /first_slot. qed.
lemma first_slot_cons ['a] (p : 'a -> bool) x xs :
  first_slot p (x :: xs) =
    if p x then 1 else if first_slot p xs = 0 then 0 else first_slot p xs + 1.
proof. by rewrite /first_slot. qed.
lemma first_slot_bounds ['a] (p : 'a -> bool) xs :
  0 <= first_slot p xs <= size xs.
proof. elim xs => [|x xs ih]; rewrite ?first_slot_nil ?first_slot_cons /=; smt(). qed.
lemma first_slot_zero ['a] (p : 'a -> bool) xs :
  first_slot p xs = 0 <=> all (fun x => !p x) xs.
proof.
  elim xs => [|x xs ih]; rewrite ?first_slot_nil ?first_slot_cons /=.
  + trivial.
  have hb := first_slot_bounds p xs; smt().
qed.
lemma first_slot_hit ['a] (p : 'a -> bool) pre a post :
  p a => all (fun x => !p x) pre =>
  first_slot p (pre ++ a :: post) = size pre + 1.
proof.
  move=> ha; elim pre => [|x xs ih]; rewrite /= first_slot_cons; smt(size_ge0).
qed.
lemma first_slot_rcons ['a] (p : 'a -> bool) xs x :
  first_slot p (rcons xs x) =
    if first_slot p xs = 0 then (if p x then size xs + 1 else 0)
    else first_slot p xs.
proof.
  elim xs => [|y ys ih]; rewrite ?first_slot_nil ?first_slot_cons /=.
  + by rewrite first_slot_cons first_slot_nil.
  have hb := first_slot_bounds p ys; rewrite first_slot_cons ih; smt().
qed.
lemma first_slot_mkseq_zero ['a] (p : 'a -> bool) (f : int -> 'a) n :
  (forall i, 0 <= i < n => !p (f i)) => first_slot p (mkseq f n) = 0.
proof. move=> h; rewrite first_slot_zero allP; smt(mkseqP). qed.
lemma first_slot_cat ['a] (p : 'a -> bool) xs ys :
  first_slot p (xs ++ ys) =
    if first_slot p xs = 0 then
      (if first_slot p ys = 0 then 0 else size xs + first_slot p ys)
    else first_slot p xs.
proof.
  elim xs => [|x xs ih]; rewrite ?first_slot_nil ?first_slot_cons /=; first smt().
  have hx := first_slot_bounds p xs.
  have hy := first_slot_bounds p ys.
  rewrite first_slot_cons ih; smt().
qed.
lemma first_slot_mkseq_hit ['a] (p : 'a -> bool) (f : int -> 'a) n i :
  0 <= i < n => p (f i) => (forall j, 0 <= j < i => !p (f j)) =>
  first_slot p (mkseq f n) = i + 1.
proof.
  move=> hi ha hp.
  have he : n = i + (n-i) by ring.
  rewrite he mkseq_add 1:/# 1:/#.
  rewrite first_slot_cat (first_slot_mkseq_zero p f i hp) /=.
  rewrite mkseqSr_minus 1:/# first_slot_cons /= ha /= size_mkseq; smt().
qed.
lemma signed_difference_zero (a b : int) : (a-b = 0) = (a=b).
proof. smt(). qed.
lemma wots_first_slot_common digests :
  wots_first_slot digests = first_slot (fun d => wots_sum d = wots_target) digests.
proof.
  rewrite /wots_first_slot /first_slot.
  congr; apply fun_ext => d; apply fun_ext => n; by rewrite signed_difference_zero.
qed.
lemma fors_first_slot_common digests :
  fors_first_slot digests = first_slot (fun d => fors_zero_field d = 0) digests.
proof. by rewrite /fors_first_slot /first_slot. qed.
lemma backend_history_nil f h : backend_history f h [] = h.
proof. by rewrite /backend_history. qed.
lemma backend_history_rcons f h xs x :
  backend_history f h (rcons xs x) = remember (backend_history f h xs) x (f x).
proof. by rewrite /backend_history foldl_rcons. qed.
lemma remember_consistent f h x : backend_consistent h f =>
  backend_consistent (remember h x (f x)) f.
proof. rewrite /remember /backend_consistent; smt(get_setE). qed.
lemma remember_preserves h x y z : z \in h => (remember h x y).[z] = h.[z].
proof. rewrite /remember; smt(get_setE). qed.
lemma backend_empty_consistent f : backend_consistent empty f.
proof. rewrite /backend_consistent; smt(emptyE). qed.
lemma backend_history_preserves f h xs z : z \in h =>
  (backend_history f h xs).[z] = h.[z].
proof.
  elim xs h => [h|x xs ih h]; first by rewrite backend_history_nil.
  move=> hz.
  have hr := remember_preserves h x (f x) z hz.
  have hm : z \in remember h x (f x) by smt(domE).
  have he := ih (remember h x (f x)) hm.
  by move: he; rewrite /backend_history /= hr.
qed.
lemma fixed_init f0 :
  hoare[FixedBackend.init : f = f0 ==>
    FixedBackend.fn = f0 /\ FixedBackend.history = empty /\
    backend_consistent FixedBackend.history f0 /\ FixedBackend.calls = 0].
proof. proc; auto; rewrite /backend_consistent; smt(emptyE). qed.
lemma fixed_hash f h x0 c :
  hoare[FixedBackend.hash :
    FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ x = x0 /\ FixedBackend.calls = c ==>
    res = f x0 /\ FixedBackend.fn = f /\
    FixedBackend.history = remember h x0 (f x0) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c + 1].
proof.
  proc; sp 1; if; auto => />;
    rewrite /remember /backend_consistent;
    smt(get_setE get_set_sameE domE).
qed.
lemma fixed_hash_ll : islossless FixedBackend.hash.
proof. proc; auto. qed.
lemma fixed_derive f h tail0 c key0 :
  hoare[FixedPrefix.derive :
    FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ tail = tail0 /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = f (key0 ++ tail0) /\ FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = remember h (key0 ++ tail0) (f (key0 ++ tail0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c + 1].
proof. proc; call (fixed_hash f h (key0 ++ tail0) c); auto. qed.
lemma fixed_derive_ll : islossless FixedPrefix.derive.
proof. proc; call fixed_hash_ll; auto. qed.
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
