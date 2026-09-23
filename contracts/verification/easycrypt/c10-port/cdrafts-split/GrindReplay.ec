(* An accepted cached nonce is a deterministic witness against exhaustion.
   Arbitrary intervening queries are harmless while the two entries persist. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind C10Counter C10HashDomains.

lemma hash_keeps_pair xr xh rd0 hd0 x0 :
  hoare[Shared.hash :
    Shared.history.[xr] = Some rd0 /\ Shared.history.[xh] = Some hd0 /\ x = x0 ==>
    Shared.history.[xr] = Some rd0 /\ Shared.history.[xh] = Some hd0 /\
    (x0 = xr => res = rd0) /\ (x0 = xh => res = hd0)].
proof.
  proc; sp 1; if; auto; smt(get_setE get_set_sameE domE).
qed.

lemma grind_cached_success secret0 random0 message0 seed0 root0 j rd0 hd0 :
  0 <= j < signing_budget => accept_digest hd0 =>
  hoare[StatefulGrind(Shared).run :
    secret = secret0 /\ random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    Shared.history.[r_input secret0 random0 message0 (U32.insubd j)] = Some rd0 /\
    Shared.history.[hmsg_input seed0 root0 (compact_r rd0 ++ nseq 16 0) message0] = Some hd0 ==>
    res <> None].
proof.
  move=> hj ha; proc.
  while (secret = secret0 /\ random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    Shared.history.[r_input secret0 random0 message0 (U32.insubd j)] = Some rd0 /\
    Shared.history.[hmsg_input seed0 root0 (compact_r rd0 ++ nseq 16 0) message0] = Some hd0 /\
    (result = None => 0 <= i <= j)).
  + exists* i; elim* => i0.
    seq 2 : (secret = secret0 /\ random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
      Shared.history.[r_input secret0 random0 message0 (U32.insubd j)] = Some rd0 /\
      Shared.history.[hmsg_input seed0 root0 (compact_r rd0 ++ nseq 16 0) message0] = Some hd0 /\
      result = None /\ 0 <= i /\ i = i0 /\ i0 <= j /\ (i0 = j => r = compact_r rd0)).
    - wp; call (hash_keeps_pair
        (r_input secret0 random0 message0 (U32.insubd j))
        (hmsg_input seed0 root0 (compact_r rd0 ++ nseq 16 0) message0) rd0 hd0
        (r_input secret0 random0 message0 (U32.insubd i0))); auto; smt().
    wp; exists* r; elim* => r0.
    call (hash_keeps_pair
      (r_input secret0 random0 message0 (U32.insubd j))
      (hmsg_input seed0 root0 (compact_r rd0 ++ nseq 16 0) message0) rd0 hd0
      (hmsg_input seed0 root0 (r0 ++ nseq 16 0) message0)).
    auto; smt().
  auto; smt().
qed.
