(* Paired acceptance inside actual bounded searches. The existing Shared
   oracle supplies 256-bit outputs under its valid-history invariant. Results,
   history and counters are preserved; no pure-SHA/oracle identification. *)
require import AllCore List IntDiv FMap.
require import C10RawOracle C10Bytes C10Counter C10RawGrind RawWots RoleGrind.
require import PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import C10Representation C10AcceptanceBridge C10CallerInputBridge ShuffleBytes.

lemma shared_init_valid :
  hoare[Shared.init : true ==> valid_history Shared.history].
proof. by proc; auto; rewrite /valid_history; smt(emptyE).
qed.

lemma wots_accept_bits d : size d = 256 =>
  count_accepts d = (wots_sum (bits_to_bytes d) = wots_target).
proof.
  move=> hd.
  have hb := shuffle_bytes_valid d.
  have hs : size (bits_to_bytes d) = 32 by rewrite bits_to_bytes_size hd.
  have he := wots_accept_common (bits_to_bytes d) hs hb.
  by move: he; rewrite bits_bytes_roundtrip 1:hd.
qed.

lemma fors_accept_bits d : size d = 256 =>
  accept_digest d = (fors_zero_field (bits_to_bytes d) = 0).
proof.
  move=> hd.
  have hb := shuffle_bytes_valid d.
  have hs : size (bits_to_bytes d) = 32 by rewrite bits_to_bytes_size hd.
  have he := fors_accept_common (bits_to_bytes d) hs hb.
  by move: he; rewrite bits_bytes_roundtrip 1:hd.
qed.

lemma shared_hash_paired :
  equiv[Shared.hash ~ Shared.hash :
    ={x,glob Shared} /\ valid_history Shared.history{1} ==>
    ={res,glob Shared} /\ valid_history Shared.history{1} /\ size res{1} = 256].
proof.
  conseq (_ : ={x,glob Shared} ==> ={res,glob Shared}) hash_width hash_width => //.
  by sim.
qed.

lemma physical_hash_paired :
  equiv[Physical.hash ~ Physical.hash :
    ={x,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1} /\ size res{1} = 256].
proof. by proc; call shared_hash_paired; auto.
qed.

lemma physical_derive_paired :
  equiv[Physical.derive ~ Physical.derive :
    ={tail,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1} /\ size res{1} = 256].
proof. by proc; call shared_hash_paired; auto.
qed.

module PairedAcceptanceWots (O : PreparationOracle) = {
  proc count(seed : raw_input, layer tree kp : int, message : raw_input) : (int * digest) option = {
    var i, d, result;
    i <- 0; result <- None;
    while (i < signing_budget /\ result = None) {
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
    return if result = None then Some ([],[]) else result;
  }
}.

lemma paired_wots_count :
  equiv[CommonInputWots(PreparationView(Physical)).count ~
        PairedAcceptanceWots(PreparationView(Physical)).count :
    ={seed,layer,tree,kp,message,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; while (={seed,layer,tree,kp,message,i,result,glob Physical} /\
    valid_history Shared.history{1}).
  + wp; call physical_hash_paired; auto => /> *.
    by rewrite wots_accept_bits.
  by auto.
qed.

lemma caller_chain_history :
  hoare[CommonInputWots(PreparationView(Physical)).chain :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  proc; while (valid_history Shared.history).
  + wp; inline Physical.hash; wp; call hash_width; auto.
  by auto.
qed.

lemma caller_chain_paired :
  equiv[CommonInputWots(PreparationView(Physical)).chain ~
        CommonInputWots(PreparationView(Physical)).chain :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  conseq (_ : ={arg,glob Physical} ==> ={res,glob Physical})
    caller_chain_history caller_chain_history => //.
  by sim.
qed.

lemma paired_wots_recover :
  equiv[CommonInputWots(PreparationView(Physical)).recover ~
        PairedAcceptanceWots(PreparationView(Physical)).recover :
    ={seed,layer,tree,kp,message,sigma,count,glob Physical} /\
    valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; seq 1 1 : (={seed,layer,tree,kp,message,sigma,count,d,glob Physical} /\
    valid_history Shared.history{1} /\ size d{1} = 256).
  + by call physical_hash_paired; auto.
  sp 1 1; if; first by auto => /> &m hh hd; rewrite (wots_accept_bits d{m} hd).
  + wp; call physical_hash_paired; wp.
    while (={seed,layer,tree,kp,sigma,d,i,elements,glob Physical} /\
      valid_history Shared.history{1}).
    - by wp; call caller_chain_paired; auto.
    by auto.
  by auto.
qed.

lemma paired_nonce_grind :
  equiv[CommonInputGrind(Physical).run ~ PairedAcceptanceGrind(Physical).run :
    ={random,message,seed,root,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; while (={random,message,seed,root,i,result,glob Physical} /\
    valid_history Shared.history{1}).
  + wp; call physical_hash_paired; wp; call physical_derive_paired.
    auto => /> &m hh hi rd rh hhr hrd hd hh2 hhh hhd.
    by rewrite (fors_accept_bits hd hhd).
  by auto.
qed.

lemma raw_wots_count_paired :
  equiv[RawWots(PreparationView(Physical)).count ~
        PairedAcceptanceWots(PreparationView(Physical)).count :
    ={seed,layer,tree,kp,message,glob Physical} /\
    caller_fields layer{1} tree{1} kp{1} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  transitivity CommonInputWots(PreparationView(Physical)).count
    (={seed,layer,tree,kp,message,glob Physical} /\
      caller_fields layer{1} tree{1} kp{1} ==> ={res,glob Physical})
    (={seed,layer,tree,kp,message,glob Physical} /\ valid_history Shared.history{1} ==>
      ={res,glob Physical} /\ valid_history Shared.history{1}) => //.
  + smt().
  + exact (caller_wots_count (PreparationView(Physical))).
  exact paired_wots_count.
qed.

lemma raw_wots_recover_paired :
  equiv[RawWots(PreparationView(Physical)).recover ~
        PairedAcceptanceWots(PreparationView(Physical)).recover :
    ={seed,layer,tree,kp,message,sigma,count,glob Physical} /\
    caller_fields layer{1} tree{1} kp{1} /\ 0 <= count{1} < 4294967296 /\
    valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  transitivity CommonInputWots(PreparationView(Physical)).recover
    (={seed,layer,tree,kp,message,sigma,count,glob Physical} /\
      caller_fields layer{1} tree{1} kp{1} /\ 0 <= count{1} < 4294967296 ==>
      ={res,glob Physical})
    (={seed,layer,tree,kp,message,sigma,count,glob Physical} /\
      valid_history Shared.history{1} ==>
      ={res,glob Physical} /\ valid_history Shared.history{1}) => //.
  + smt().
  + exact (caller_wots_recover (PreparationView(Physical))).
  exact paired_wots_recover.
qed.

lemma role_nonce_grind_paired :
  equiv[RoleGrind(Physical).run ~ PairedAcceptanceGrind(Physical).run :
    ={random,message,seed,root,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  transitivity CommonInputGrind(Physical).run
    (={random,message,seed,root,glob Physical} ==> ={res,glob Physical})
    (={random,message,seed,root,glob Physical} /\ valid_history Shared.history{1} ==>
      ={res,glob Physical} /\ valid_history Shared.history{1}) => //.
  + smt().
  + exact (caller_nonce_grind Physical).
  exact paired_nonce_grind.
qed.

lemma stateful_nonce_grind_paired :
  equiv[StatefulGrind(Shared).run ~ PairedAcceptanceGrind(Physical).run :
    ={random,message,seed,root,glob Shared} /\ secret{1} = Physical.key{2} /\
    valid_history Shared.history{1} ==>
    ={res,glob Shared} /\ valid_history Shared.history{1}].
proof.
  transitivity RoleGrind(Physical).run
    (={random,message,seed,root,glob Shared} /\ secret{1} = Physical.key{2} ==>
      ={res,glob Shared})
    (={random,message,seed,root,glob Physical} /\ valid_history Shared.history{1} ==>
      ={res,glob Physical} /\ valid_history Shared.history{1}) => //.
  + smt().
  + exact grind_refinement.
  exact role_nonce_grind_paired.
qed.
