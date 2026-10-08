(* A selected private entry can be sampled without adding a client or signer query. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid.

module PrivateMemoSample = {
  proc get(x : raw_input) : digest = {
    var y;
    if (x \notin Independent.secrethistory) {
      y <$ full_digest; Independent.secrethistory.[x] <- y;
    }
    return oget Independent.secrethistory.[x];
  }
}.
module PrivateValueSample = {
  var target : raw_input
  var value : digest
  proc sample() : unit = { value <@ PrivateMemoSample.get(target); }
}.

lemma private_value_sample_get :
  eager [PrivateValueSample.sample();, PrivateMemoSample.get ~ PrivateMemoSample.get, PrivateValueSample.sample(); :
    ={arg,glob Independent,glob PrivateValueSample} ==>
    ={res,glob Independent,glob PrivateValueSample}].
proof.
  eager proc; inline *.
  case (x{1}=PrivateValueSample.target{1}).
  + sp 1 0; if{1}.
    - rcondt{2} 1; first by auto; smt().
      seq 2 2 : (={glob Independent,PrivateValueSample.target,x} /\
        x{1} \in Independent.secrethistory{1} /\ x{1}=PrivateValueSample.target{1} /\
        x0{1}=PrivateValueSample.target{1}).
      * auto; smt(mem_set).
      rcondf{1} 2; first by auto; smt().
      rcondf{2} 3; first by auto; smt().
      auto; smt().
    rcondf{2} 1; first by auto; smt().
    rcondf{1} 2; first by auto; smt().
    rcondf{2} 3; first by auto; smt().
    auto; smt().
  case (PrivateValueSample.target{1} \in Independent.secrethistory{1});
    case (x{1} \in Independent.secrethistory{1}).
  + rcondf{1} 2; first by auto.
    rcondf{1} 3; first by auto.
    rcondf{2} 1; first by auto.
    rcondf{2} 3; first by auto.
    auto; smt().
  + rcondf{1} 2; first by auto.
    rcondt{1} 3; first by auto.
    rcondt{2} 1; first by auto.
    rcondf{2} 5; first by auto; smt(mem_set).
    auto; smt().
  + rcondt{1} 2; first by auto.
    rcondf{1} 5; first by auto; smt(mem_set).
    rcondf{2} 1; first by auto.
    rcondt{2} 3; first by auto.
    auto; smt(get_setE).
  rcondt{1} 2; first by auto.
  rcondt{1} 5; first by auto; smt(mem_set).
  rcondt{2} 1; first by auto.
  rcondt{2} 5; first by auto; smt(mem_set).
  sp 1 0; swap{1} 4 -2; swap{2} 5 -4.
  auto; smt(get_setE set_set_neqE).
qed.
