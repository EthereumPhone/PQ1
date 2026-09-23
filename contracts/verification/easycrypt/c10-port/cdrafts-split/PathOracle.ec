(* Public hashing preserves a recorded prefix and records the current entry. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen.
require import PersistentGrind AcceptedContexts PathReplay.

lemma hash_preserves_path f st auth value0 x0 :
  hoare[Independent.hash :
    path_recorded Independent.rawhistory f st auth /\
    path_value Independent.rawhistory f st auth = value0 /\ x = x0 ==>
    path_recorded Independent.rawhistory f st auth /\
    path_value Independent.rawhistory f st auth = value0 /\
    Independent.rawhistory.[x0] = Some res].
proof.
  proc; sp 1; if; auto;
    smt(path_recorded_extends extends_insert get_set_sameE domE).
qed.

lemma hash_preserves_path_entry f st auth value0 x0 entry d0 :
  hoare[Independent.hash :
    path_recorded Independent.rawhistory f st auth /\
    path_value Independent.rawhistory f st auth = value0 /\ x = x0 /\
    Independent.rawhistory.[entry] = Some d0 ==>
    path_recorded Independent.rawhistory f st auth /\
    path_value Independent.rawhistory f st auth = value0 /\
    Independent.rawhistory.[x0] = Some res /\
    Independent.rawhistory.[entry] = Some d0].
proof.
  proc; sp 1; if; auto;
    smt(path_recorded_extends extends_insert get_set_sameE get_setE domE).
qed.

lemma hash_keeps_path_root f st auth root0 :
  hoare[Independent.hash :
    path_recorded Independent.rawhistory f st auth /\
    (path_value Independent.rawhistory f st auth).`1 = root0 ==>
    path_recorded Independent.rawhistory f st auth /\
    (path_value Independent.rawhistory f st auth).`1 = root0].
proof.
  proc; sp 1; if; auto; smt(path_recorded_extends extends_insert).
qed.

lemma hash_keeps_path_root_entry f st auth root0 entry d0 :
  hoare[Independent.hash :
    path_recorded Independent.rawhistory f st auth /\
    (path_value Independent.rawhistory f st auth).`1 = root0 /\
    Independent.rawhistory.[entry] = Some d0 ==>
    path_recorded Independent.rawhistory f st auth /\
    (path_value Independent.rawhistory f st auth).`1 = root0 /\
    Independent.rawhistory.[entry] = Some d0].
proof.
  proc; sp 1; if; auto;
    smt(path_recorded_extends extends_insert get_setE domE).
qed.
