(* The actual shared-table grind leaves its successful two-query witness
   in persistent history, so the replay theorem applies to its own output. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind C10Counter C10HashDomains.

op accepted_witness (h : (raw_input,digest) fmap) secret random message seed root =
  exists j rd hd, 0 <= j < signing_budget /\ accept_digest hd /\
    h.[r_input secret random message (U32.insubd j)] = Some rd /\
    h.[hmsg_input seed root (compact_r rd ++ nseq 16 0) message] = Some hd.

lemma hash_records x0 :
  hoare[Shared.hash : x = x0 ==> Shared.history.[x0] = Some res].
proof. proc; sp 1; if; auto; smt(get_set_sameE domE). qed.

lemma hash_records_keeps xr rd0 x0 :
  hoare[Shared.hash : Shared.history.[xr] = Some rd0 /\ x = x0 ==>
    Shared.history.[xr] = Some rd0 /\ Shared.history.[x0] = Some res].
proof. proc; sp 1; if; auto; smt(get_setE get_set_sameE domE). qed.

lemma grind_records_success sk0 rng0 msg0 ps0 pk0 :
  hoare[StatefulGrind(Shared).run :
    secret = sk0 /\ random = rng0 /\ message = msg0 /\ seed = ps0 /\ root = pk0 ==>
    res <> None => accepted_witness Shared.history sk0 rng0 msg0 ps0 pk0].
proof.
  proc; while (secret = sk0 /\ random = rng0 /\ message = msg0 /\ seed = ps0 /\ root = pk0 /\
    0 <= i <= signing_budget /\
    (result <> None => accepted_witness Shared.history secret random message seed root)).
  + exists* i, secret, random, message, seed, root;
    elim* => i0 sk rng msg ps pk.
    seq 2 : (0 <= i /\ i = i0 /\ i0 < signing_budget /\ result = None /\
      sk = sk0 /\ rng = rng0 /\ msg = msg0 /\ ps = ps0 /\ pk = pk0 /\
      secret = sk /\ random = rng /\ message = msg /\ seed = ps /\ root = pk /\
      Shared.history.[r_input sk rng msg (U32.insubd i0)] = Some rd /\ r = compact_r rd).
    - wp; call (hash_records (r_input sk rng msg (U32.insubd i0))); auto; smt().
    wp; exists* rd; elim* => rd0.
    call (hash_records_keeps (r_input sk rng msg (U32.insubd i0)) rd0
      (hmsg_input ps pk (compact_r rd0 ++ nseq 16 0) msg)).
    auto; rewrite /accepted_witness; smt().
  auto; smt().
qed.
