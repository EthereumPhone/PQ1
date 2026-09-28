(* Stateful secret-keyed R/H_msg search through one raw oracle, including repeated inputs and worst-case query cost. *)
require import AllCore List Distr C10RawOracle C10Bytes C10HashDomains C10Randomizer C10Counter.

(* Stateful classical R/H_msg search using one shared raw oracle. This model
   retains secret-keyed R derivation and repeated inputs; no IID shortcut. *)

op accept_digest (digest : bool list) =
  take 11 (drop 132 digest) = nseq 11 false.

op compact_r (digest : bool list) = bits_to_bytes (truncate_r digest).

module StatefulGrind (H : Hash) = {
  proc run(secret random message seed root : int list) : (int list * bool list) option = {
    var i : int;
    var rd, hd : bool list;
    var r : int list;
    var result : (int list * bool list) option;
    i <- 0; result <- None;
    while (i < signing_budget /\ result = None) {
      rd <@ H.hash(r_input secret random message (U32.insubd i));
      r <- compact_r rd;
      hd <@ H.hash(hmsg_input seed root (r ++ nseq 16 0) message);
      if (accept_digest hd) { result <- Some (r,hd); }
      i <- i+1;
    }
    return result;
  }
}.

lemma grind_cost c0 d0 :
  hoare[StatefulGrind(Shared).run : Shared.calls = c0 /\ Shared.draws = d0 ==>
    c0 <= Shared.calls <= c0 + 2*signing_budget /\
    d0 <= Shared.draws <= d0 + 2*signing_budget].
proof.
  proc; while (0 <= i <= signing_budget /\ Shared.calls = c0+2*i /\
    d0 <= Shared.draws <= d0+2*i).
  + exists* i; elim* => i0.
    seq 1 : (i = i0 /\ 0 <= i0 < signing_budget /\
      Shared.calls = c0+2*i0+1 /\ d0 <= Shared.draws <= d0+2*i0+1).
    - exists* Shared.draws; elim* => d1.
      call (hash_cost (c0+2*i0) d1); auto; smt().
    wp; exists* Shared.draws; elim* => d2.
    call (hash_cost (c0+2*i0+1) d2).
    by auto; smt().
  by auto; smt().
qed.

lemma grind_ll : islossless StatefulGrind(Shared).run.
proof.
  proc; while true (signing_budget-i).
  + move=> z; wp; call hash_ll; wp; call hash_ll; auto; smt().
  by auto; smt().
qed.

lemma grind_accepts :
  hoare[StatefulGrind(Shared).run : true ==> res <> None => accept_digest (oget res).`2].
proof.
  proc; while (result <> None => accept_digest (oget result).`2).
  + wp; call (_ : true ==> true); first by conseq hash_ll.
    wp; call (_ : true ==> true); first by conseq hash_ll.
    auto; smt().
  by auto.
qed.

lemma randomizer_width (digest : bool list) : size digest = 256 => size (compact_r digest) = 16.
proof. move=> hs; rewrite /compact_r bits_to_bytes_size /truncate_r; smt(size_drop). qed.

lemma grind_width :
  hoare[StatefulGrind(Shared).run : valid_history Shared.history ==>
    valid_history Shared.history /\
    (res <> None => size (oget res).`1 = 16 /\ size (oget res).`2 = 256)].
proof.
  proc; while (valid_history Shared.history /\
    (result <> None => size (oget result).`1 = 16 /\ size (oget result).`2 = 256)).
  + seq 1 : (valid_history Shared.history /\ size rd = 256 /\ result = None).
    - by call hash_width; auto.
    wp; call hash_width; auto; smt(randomizer_width).
  by auto.
qed.
