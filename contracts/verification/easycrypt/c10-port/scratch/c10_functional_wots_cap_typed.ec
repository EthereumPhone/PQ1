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
    while (i < signing_budget-1 /\ result = None) {
      d <@ O.hash(wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) i);
      if (wots_sum (bits_to_bytes d) = wots_target) { result <- Some (i,d); }
      i <- i+1;
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
