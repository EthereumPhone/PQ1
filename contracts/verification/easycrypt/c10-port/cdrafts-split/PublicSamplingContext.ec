(* Early public sampling commutes with the actual logged hash oracle. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PublicTargetSampling.

lemma public_target_sample_hash :
  eager [PublicTargetSample.sample();, Independent.hash ~ Independent.hash, PublicTargetSample.sample(); :
    ={arg,glob Independent,glob PublicTargetSample} ==>
    ={res,glob Independent,glob PublicTargetSample}].
proof.
  eager proc; swap{1} 1 1.
  seq 1 1 : (={x,glob Independent,glob PublicTargetSample}); first auto.
  inline *.
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

lemma public_target_sample_derive :
  eager [PublicTargetSample.sample();, Independent.derive ~ Independent.derive, PublicTargetSample.sample(); :
    ={arg,glob Independent,glob PublicTargetSample} ==>
    ={res,glob Independent,glob PublicTargetSample}].
proof.
  eager proc; inline *.
  swap{1} [1..3] 2.
  sim.
qed.

lemma public_target_sample_context
  (A <: PrefixContext {-Independent,-PublicMemoSample,-PublicTargetSample}) :
  eager [PublicTargetSample.sample();, A(Independent).run ~ A(Independent).run, PublicTargetSample.sample(); :
    ={glob A,glob Independent,glob PublicTargetSample} ==>
    ={res,glob A,glob Independent,glob PublicTargetSample}].
proof.
  eager proc (={glob Independent,glob PublicTargetSample}) => //; try by sim.
  + apply public_target_sample_hash.
  apply public_target_sample_derive.
qed.
