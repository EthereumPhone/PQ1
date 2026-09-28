(* Accepted history in the independent-table intermediate game. The final
   physical game is connected once for the entire adaptive context. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind C10Counter C10HashDomains.
require import PrefixGuess PrefixHybrid RoleGrind RTailFresh.

op ideal_witness (secret raw : (raw_input,digest) fmap) random message seed root =
  exists j rd hd, 0 <= j < signing_budget /\ accept_digest hd /\
    secret.[r_query random message j] = Some rd /\
    raw.[hmsg_input seed root (compact_r rd ++ nseq 16 0) message] = Some hd.

lemma ideal_derive_pair xr xh rd0 hd0 tail0 :
  hoare[Independent.derive : Independent.secrethistory.[xr] = Some rd0 /\
    Independent.rawhistory.[xh] = Some hd0 /\ tail = tail0 ==>
    Independent.secrethistory.[xr] = Some rd0 /\ Independent.rawhistory.[xh] = Some hd0 /\
    (tail0 = xr => res = rd0)].
proof. proc; if; auto; smt(get_setE get_set_sameE domE). qed.

lemma ideal_hash_pair xr xh rd0 hd0 x0 :
  hoare[Independent.hash : Independent.secrethistory.[xr] = Some rd0 /\
    Independent.rawhistory.[xh] = Some hd0 /\ x = x0 ==>
    Independent.secrethistory.[xr] = Some rd0 /\ Independent.rawhistory.[xh] = Some hd0 /\
    (x0 = xh => res = hd0)].
proof. proc; sp 1; if; auto; smt(get_setE get_set_sameE domE). qed.

lemma ideal_cached_success random0 message0 seed0 root0 j rd0 hd0 :
  0 <= j < signing_budget => accept_digest hd0 =>
  hoare[RoleGrind(Independent).run :
    random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    Independent.secrethistory.[r_query random0 message0 j] = Some rd0 /\
    Independent.rawhistory.[hmsg_input seed0 root0 (compact_r rd0 ++ nseq 16 0) message0] = Some hd0 ==>
    res <> None].
proof.
  move=> hj ha; proc.
  while (random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    Independent.secrethistory.[r_query random0 message0 j] = Some rd0 /\
    Independent.rawhistory.[hmsg_input seed0 root0 (compact_r rd0 ++ nseq 16 0) message0] = Some hd0 /\
    (result = None => 0 <= i <= j)).
  + exists* i; elim* => i0.
    seq 2 : (random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
      Independent.secrethistory.[r_query random0 message0 j] = Some rd0 /\
      Independent.rawhistory.[hmsg_input seed0 root0 (compact_r rd0 ++ nseq 16 0) message0] = Some hd0 /\
      result = None /\ 0 <= i /\ i = i0 /\ i0 <= j /\ (i0 = j => r = compact_r rd0)).
    - wp; call (ideal_derive_pair (r_query random0 message0 j)
        (hmsg_input seed0 root0 (compact_r rd0 ++ nseq 16 0) message0) rd0 hd0
        (r_query random0 message0 i0)); auto; rewrite /r_query; smt().
    wp; exists* r; elim* => r0.
    call (ideal_hash_pair (r_query random0 message0 j)
      (hmsg_input seed0 root0 (compact_r rd0 ++ nseq 16 0) message0) rd0 hd0
      (hmsg_input seed0 root0 (r0 ++ nseq 16 0) message0)); auto; smt().
  auto; smt().
qed.

lemma ideal_witness_failure_zero random0 message0 seed0 root0 &m :
  ideal_witness Independent.secrethistory{m} Independent.rawhistory{m} random0 message0 seed0 root0 =>
  Pr[RoleGrind(Independent).run(random0,message0,seed0,root0) @ &m : res = None] = 0%r.
proof.
  rewrite /ideal_witness => hex.
  elim hex => j rd0 hd0 [#] hj0 hj1 ha hr hh.
  have hj : 0 <= j < signing_budget by smt().
  byphoare (_ : random = random0 /\ message = message0 /\ seed = seed0 /\ root = root0 /\
    Independent.secrethistory.[r_query random0 message0 j] = Some rd0 /\
    Independent.rawhistory.[hmsg_input seed0 root0 (compact_r rd0 ++ nseq 16 0) message0] = Some hd0 ==>
    res = None) => //.
  hoare; conseq (ideal_cached_success random0 message0 seed0 root0 j rd0 hd0 hj ha); smt().
qed.

lemma ideal_derive_records tail0 :
  hoare[Independent.derive : tail = tail0 ==> Independent.secrethistory.[tail0] = Some res].
proof. proc; if; auto; smt(get_set_sameE domE). qed.

lemma ideal_hash_records xr rd0 x0 :
  hoare[Independent.hash : Independent.secrethistory.[xr] = Some rd0 /\ x = x0 ==>
    Independent.secrethistory.[xr] = Some rd0 /\ Independent.rawhistory.[x0] = Some res].
proof. proc; sp 1; if; auto; smt(get_set_sameE domE). qed.

lemma ideal_grind_records rng0 msg0 ps0 pk0 :
  hoare[RoleGrind(Independent).run : random = rng0 /\ message = msg0 /\ seed = ps0 /\ root = pk0 ==>
    res <> None => ideal_witness Independent.secrethistory Independent.rawhistory rng0 msg0 ps0 pk0].
proof.
  proc; while (random = rng0 /\ message = msg0 /\ seed = ps0 /\ root = pk0 /\
    0 <= i <= signing_budget /\ (result <> None =>
      ideal_witness Independent.secrethistory Independent.rawhistory random message seed root)).
  + exists* i; elim* => i0.
    seq 2 : (0 <= i /\ i = i0 /\ i0 < signing_budget /\ result = None /\
      random = rng0 /\ message = msg0 /\ seed = ps0 /\ root = pk0 /\
      Independent.secrethistory.[r_query rng0 msg0 i0] = Some rd /\ r = compact_r rd).
    - wp; call (ideal_derive_records (r_query rng0 msg0 i0)); auto; rewrite /r_query; smt().
    wp; exists* rd; elim* => rd0.
    call (ideal_hash_records (r_query rng0 msg0 i0) rd0
      (hmsg_input ps0 pk0 (compact_r rd0 ++ nseq 16 0) msg0)).
    auto; rewrite /ideal_witness; smt().
  auto; smt().
qed.
