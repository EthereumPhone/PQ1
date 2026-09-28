(* Manual raw-oracle transcription of keygen_pk and compute_subtree_root.
   This is not an extraction theorem. Stack order is represented by a list. *)
require import AllCore List Distr BitEncoding IntDiv.
require import C10RawOracle C10RawGrind C10Bytes C10Counter.
require import PrefixGuess PrefixHybrid RoleGrindCost KeygenPrefixes.
import BS2Int.

op be n x = bits_to_bytes (int2bs (8*n) x).
op address layer tree kind kp ci cp ha =
  be 4 layer ++ be 8 tree ++ be 4 kind ++ be 4 kp ++ be 4 ci ++ be 4 cp ++ be 4 ha.
op wots_tail layer tree kp ci = be 4 layer ++ be 32 tree ++ be 4 kp ++ be 4 ci.
(* Totalization outside the 256-bit oracle support; identical on valid digests. *)
op node (d : digest) = take 16 (compact_r d ++ nseq 16 0).
op pad (x : raw_input) = x ++ nseq 16 0.

lemma node_width d : size (node d) = 16.
proof. rewrite /node size_take 1:// size_cat size_nseq; smt(size_ge0). qed.
lemma node_exact d : size d = 256 => node d = compact_r d.
proof.
  move=> hd; have hw := randomizer_width d hd.
  by rewrite /node take_cat hw /= take0 cats0.
qed.

module RawKeygen (O : PreparationOracle) = {
  proc leaf(seed : raw_input, layer tree kp : int) : raw_input = {
    var i, j, d, current, elements;
    i <- 0; elements <- [];
    while (i < 43) {
      d <@ O.wots(wots_tail layer tree kp i);
      current <- node d; j <- 0;
      while (j < 7) {
        d <@ O.hash(seed ++ address layer tree 0 kp i j 0 ++ pad current);
        current <- node d; j <- j+1;
      }
      elements <- rcons elements (pad current); i <- i+1;
    }
    d <@ O.hash(seed ++ address layer tree 1 kp 0 0 0 ++ flatten elements);
    return node d;
  }
  proc root(seed : raw_input, layer tree : int) : raw_input = {
    var kp, current, height, stack, sibling, parent, d;
    kp <- 0; stack <- [];
    while (kp < 512) {
      current <@ leaf(seed,layer,tree,kp);
      height <- 0;
      while (stack <> [] /\ (head ([],0) stack).`2 = height) {
        sibling <- (head ([],0) stack).`1;
        stack <- behead stack;
        parent <- kp %/ (2^(height+1));
        d <@ O.hash(seed ++ address layer tree 2 0 0 (height+1) parent ++ pad sibling ++ pad current);
        current <- node d; height <- height+1;
      }
      stack <- (current,height)::stack; kp <- kp+1;
    }
    return (head (nseq 16 0,0) stack).`1;
  }
}.

lemma wots_public_count q0 :
  hoare[PreparationView(Independent).wots : size Independent.queries = q0 ==>
    size Independent.queries = q0].
proof. by proc; call (independent_derive_count q0); auto. qed.

lemma leaf_public_cost q0 :
  hoare[RawKeygen(PreparationView(Independent)).leaf : size Independent.queries = q0 ==>
    size Independent.queries = q0 + 302 /\ size res = 16].
proof.
  proc; call (independent_hash_count (q0+301)); wp.
  while (0 <= i <= 43 /\ size Independent.queries = q0+7*i).
  + wp; while (0 <= j <= 7 /\ size Independent.queries = q0+7*i+j).
    - exists* i, j; elim* => i0 j0; wp.
      call (independent_hash_count (q0+7*i0+j0)); auto; smt().
    wp; exists* i; elim* => i0; call (wots_public_count (q0+7*i0)); auto; smt().
  auto; smt(node_width).
qed.
