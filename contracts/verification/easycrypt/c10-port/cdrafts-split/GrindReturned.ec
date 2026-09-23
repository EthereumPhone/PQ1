(* External Q research: the returned accepted digest is the actual retained
   H_msg entry, not an unrelated accepting witness. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind C10HashDomains C10Randomizer.
require import PrefixGuess RoleGrind RawSigner RawHistoryPreservation.

lemma independent_hash_records_entry x0 :
  hoare[Independent.hash : x = x0 ==> Independent.rawhistory.[x0] = Some res].
proof. proc; sp 1; if; auto; smt(get_set_sameE domE). qed.

op returned_digest_entry h seed root message (answer : (raw_input * digest) option) =
  answer <> None =>
    h.[hmsg_input seed root ((oget answer).`1 ++ nseq 16 0) message] =
      Some (oget answer).`2 /\ accept_digest (oget answer).`2.

lemma grind_returned_entry seed0 root0 message0 :
  hoare[RoleGrind(Independent).run :
    seed = seed0 /\ root = root0 /\ message = message0 ==>
    returned_digest_entry Independent.rawhistory seed0 root0 message0 res].
proof.
  proc; while (seed = seed0 /\ root = root0 /\ message = message0 /\
    returned_digest_entry Independent.rawhistory seed0 root0 message0 result).
  + seq 2 : (seed = seed0 /\ root = root0 /\ message = message0 /\ result = None).
    - wp; call (_ : true ==> true).
      + by proc; if; auto.
      auto.
    wp; exists* r; elim* => r0.
    call (independent_hash_records_entry
      (hmsg_input seed0 root0 (r0 ++ nseq 16 0) message0)).
    auto; rewrite /returned_digest_entry; smt().
  auto; rewrite /returned_digest_entry; smt().
qed.

module type SignatureFinisher (O : PrefixOracle) = {
  proc finish(seed randomizer : raw_input, digest : digest, shuffle : raw_input) :
    raw_signature option { O.hash, O.derive }
}.

lemma finisher_keeps_entry (F <: SignatureFinisher {-Independent}) x0 d0 :
  hoare[F(Independent).finish : Independent.rawhistory.[x0] = Some d0 ==>
    Independent.rawhistory.[x0] = Some d0].
proof.
  proc (Independent.rawhistory.[x0] = Some d0) => //.
  + exact (independent_hash_keeps x0 d0).
  exact (independent_derive_keeps x0 d0).
qed.

lemma signer_finish_keeps_entry x0 d0 :
  hoare[RawSigner(Independent).finish : Independent.rawhistory.[x0] = Some d0 ==>
    Independent.rawhistory.[x0] = Some d0].
proof. exact (finisher_keeps_entry RawSigner x0 d0). qed.
