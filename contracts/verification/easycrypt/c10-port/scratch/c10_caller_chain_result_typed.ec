(* Actual EasyCrypt callers consume the paired common preimages. The same
   arbitrary oracle runs on both sides; its entire global state is preserved.
   These are caller-component equivalences, not concrete-SHA idealizations or
   a cross-kernel Rust/session theorem. *)
require import AllCore List IntDiv Ring RadixEncoding.
require import C10Bytes C10Counter C10HashDomains C10RawOracle C10RawGrind.
require import PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RoleGrind.
require import C10Representation C10HashInputBridge C10AddressInputBridge.

op caller_fields layer tree kp =
  0 <= layer < 2^32 /\ 0 <= tree < 2^64 /\ 0 <= kp < 2^32.






module CommonInputWots (O : PreparationOracle) = {
  proc count(seed : raw_input, layer tree kp : int, message : raw_input) : (int * digest) option = {
    var i, d, result;
    i <- 0; result <- None;
    while (i < signing_budget /\ result = None) {
      d <@ O.hash(wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) i);
      if (count_accepts d) { result <- Some (i,d); }
      i <- i+1;
    }
    return result;
  }
  proc chain(seed : raw_input, layer tree kp index : int, current : raw_input, start stop : int) : raw_input = {
    var j, d;
    j <- start;
    while (j < stop) {
      d <@ O.hash(th_preimage seed (address_words layer tree 0 kp index j 0) (pad_node current));
      current <- nseq 16 0; j <- j+1;
    }
    return current;
  }
  proc recover(seed : raw_input, layer tree kp : int, message : raw_input, sigma : raw_input list, count : int) : raw_input = {
    var d, result, i, current, elements;
    d <@ O.hash(wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) count);
    result <- nseq 16 0;
    if (count_accepts d) {
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




module CommonInputGrind (O : PrefixOracle) = {
  proc run(random message seed root : int list) : (int list * bool list) option = {
    var i, rd, hd, r, result;
    i <- 0; result <- None;
    while (i < signing_budget /\ result = None) {
      rd <@ O.derive(r_preimage [] random message i);
      r <- compact_r rd;
      hd <@ O.hash(hmsg_preimage seed root (pad_node r) message);
      if (accept_digest hd) { result <- Some (r,hd); }
      i <- i+1;
    }
    return result;
  }
}.


