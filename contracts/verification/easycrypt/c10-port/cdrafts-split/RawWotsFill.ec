(* Exact factoring of the shuffled signing loop after an accepted count. *)
require import AllCore List RadixEncoding.
require import C10RawOracle KeygenPrefixes RawKeygen RawWots RawShuffle.

module RawWotsFill (O : PreparationOracle) = {
  proc fill(seed : raw_input, layer tree kp : int, accepted : digest, shuffle : raw_input) : raw_input list = {
    var order, step, i, d, current, sigma;
    sigma <- nseq 43 (nseq 16 0);
    order <@ RawShuffle(O).permutation(shuffle,43);
    step <- 0;
    while (step < 43) {
      i <- nth 0 order step;
      d <@ O.wots(wots_tail layer tree kp i);
      current <@ RawWots(O).chain(seed,layer,tree,kp,i,node d,0,digit 3 accepted i);
      sigma <- put sigma i current; step <- step+1;
    }
    return sigma;
  }
  proc sign(seed : raw_input, layer tree kp : int, message shuffle : raw_input) : (raw_input list * int) option = {
    var accepted, sigma, result;
    accepted <@ RawWots(O).count(seed,layer,tree,kp,message);
    result <- None;
    if (accepted <> None) {
      sigma <@ fill(seed,layer,tree,kp,(oget accepted).`2,shuffle);
      result <- Some (sigma,(oget accepted).`1);
    }
    return result;
  }
}.

lemma raw_wots_fill_projection (O <: PreparationOracle) :
  equiv [RawWots(O).sign ~ RawWotsFill(O).sign :
    ={seed,layer,tree,kp,message,shuffle,glob O} ==> ={res,glob O}].
proof.
  proc; inline RawWotsFill(O).fill.
  seq 1 1 : (={seed,layer,tree,kp,message,shuffle,accepted,glob O}).
  + call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto.
  sp 1 1; if; auto; wp.
  while (seed{1}=seed0{2} /\ layer{1}=layer0{2} /\ tree{1}=tree0{2} /\ kp{1}=kp0{2} /\
    accepted0{2}=(oget accepted{1}).`2 /\ sigma{1}=sigma0{2} /\ ={accepted,order,step,glob O}).
  + wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto.
  wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  auto.
qed.
