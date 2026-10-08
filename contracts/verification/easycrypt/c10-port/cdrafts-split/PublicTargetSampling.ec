(* A selected public entry can be sampled without adding a client or signer query. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid.

module PublicMemoSample = {
  proc get(x : raw_input) : digest = {
    var y;
    if (x \notin Independent.rawhistory) {
      y <$ full_digest; Independent.rawhistory.[x] <- y;
    }
    return oget Independent.rawhistory.[x];
  }
}.
module PublicTargetSample = {
  var target : raw_input
  var value : digest
  proc sample() : unit = { value <@ PublicMemoSample.get(target); }
}.

lemma public_target_sample_get :
  eager [PublicTargetSample.sample();, PublicMemoSample.get ~ PublicMemoSample.get, PublicTargetSample.sample(); :
    ={arg,glob Independent,glob PublicTargetSample} ==>
    ={res,glob Independent,glob PublicTargetSample}].
proof.
  eager proc; inline *.
  case (x{1}=PublicTargetSample.target{1}).
  + sp 1 0; if{1}.
    - rcondt{2} 1; first by auto; smt().
      seq 2 2 : (={glob Independent,PublicTargetSample.target,x} /\
        x{1} \in Independent.rawhistory{1} /\ x{1}=PublicTargetSample.target{1} /\
        x0{1}=PublicTargetSample.target{1}).
      * auto; smt(mem_set).
      rcondf{1} 2; first by auto; smt().
      rcondf{2} 3; first by auto; smt().
      auto; smt().
    rcondf{2} 1; first by auto; smt().
    rcondf{1} 2; first by auto; smt().
    rcondf{2} 3; first by auto; smt().
    auto; smt().
  case (PublicTargetSample.target{1} \in Independent.rawhistory{1});
    case (x{1} \in Independent.rawhistory{1}).
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
