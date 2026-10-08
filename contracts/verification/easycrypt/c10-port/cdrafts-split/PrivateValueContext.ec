(* Preserve the selected private digest while moving its sample across a context. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrivateValueSampling.

lemma private_value_sample_derive :
  eager [PrivateValueSample.sample();, Independent.derive ~ Independent.derive, PrivateValueSample.sample(); :
    ={arg,glob Independent,glob PrivateValueSample} ==>
    ={res,glob Independent,glob PrivateValueSample}].
proof.
  eager proc; inline *.
  case (tail{1}=PrivateValueSample.target{1}).
  + sp 1 0; if{1}.
    - rcondt{2} 1; first by auto; smt().
      seq 2 2 : (={glob Independent,PrivateValueSample.target,tail} /\
        tail{1} \in Independent.secrethistory{1} /\ tail{1}=PrivateValueSample.target{1} /\
        x{1}=PrivateValueSample.target{1}).
      * auto; smt(mem_set).
      rcondf{1} 2; first by auto; smt().
      rcondf{2} 3; first by auto; smt().
      auto; smt().
    rcondf{2} 1; first by auto; smt().
    rcondf{1} 2; first by auto; smt().
    rcondf{2} 3; first by auto; smt().
    auto; smt().
  case (PrivateValueSample.target{1} \in Independent.secrethistory{1});
    case (tail{1} \in Independent.secrethistory{1}).
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

lemma private_value_sample_hash :
  eager [PrivateValueSample.sample();, Independent.hash ~ Independent.hash, PrivateValueSample.sample(); :
    ={arg,glob Independent,glob PrivateValueSample} ==>
    ={res,glob Independent,glob PrivateValueSample}].
proof. eager proc; inline *; swap{1} [1..3] 3; sim. qed.

lemma private_value_sample_context
  (A <: PrefixContext {-Independent,-PrivateMemoSample,-PrivateValueSample}) :
  eager [PrivateValueSample.sample();, A(Independent).run ~ A(Independent).run, PrivateValueSample.sample(); :
    ={glob A,glob Independent,glob PrivateValueSample} ==>
    ={res,glob A,glob Independent,glob PrivateValueSample}].
proof.
  eager proc (={glob Independent,glob PrivateValueSample}) => //; try by sim.
  + apply private_value_sample_hash.
  apply private_value_sample_derive.
qed.
