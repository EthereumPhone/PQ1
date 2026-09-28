(* External next-batch refinement of the concrete shared-table R/H_msg loop.
   All keyed derivations use the same Physical.key; no independent R key. *)
require import AllCore List Distr.
require import C10RawOracle C10Bytes C10HashDomains C10Randomizer C10Counter C10RawGrind.
require import PrefixGuess PrefixHybrid.

op r_tail (random message : int list) (nonce : counter) =
  [82;95;103;114;105;110;100] ++ random ++ message ++ nseq 28 0 ++ counter_bytes nonce.

lemma r_tail_layout secret random message nonce :
  r_input secret random message nonce = secret ++ r_tail random message nonce.
proof. by rewrite /r_input /r_tail -!catA. qed.

module RoleGrind (O : PrefixOracle) = {
  proc run(random message seed root : int list) : (int list * bool list) option = {
    var i : int;
    var rd, hd : bool list;
    var r : int list;
    var result : (int list * bool list) option;
    i <- 0; result <- None;
    while (i < signing_budget /\ result = None) {
      rd <@ O.derive(r_tail random message (U32.insubd i));
      r <- compact_r rd;
      hd <@ O.hash(hmsg_input seed root (r ++ nseq 16 0) message);
      if (accept_digest hd) { result <- Some (r,hd); }
      i <- i+1;
    }
    return result;
  }
}.

lemma grind_refinement :
  equiv[StatefulGrind(Shared).run ~ RoleGrind(Physical).run :
    ={random,message,seed,root,glob Shared} /\ secret{1} = Physical.key{2} ==>
    ={res,glob Shared}].
proof.
  proc; while (={i,result,random,message,seed,root,glob Shared} /\
    secret{1} = Physical.key{2}).
  + inline Physical.hash Physical.derive; wp; call (_ : ={x,glob Shared} ==> ={res,glob Shared}).
    - by sim.
    wp; call (_ : ={x,glob Shared} ==> ={res,glob Shared}).
    - by sim.
    by auto; smt(r_tail_layout).
  by auto.
qed.
