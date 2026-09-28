(* Actual grinding retains the separately generated top-layer root witness. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess RoleGrind.
require import PersistentGrind AcceptedContexts MonotoneHistory MerkleRootWitness.

module type SignerGrinding (O : PrefixOracle) = {
  proc run(random message seed root : raw_input) : (raw_input * digest) option { O.hash, O.derive }
}.
lemma signer_grinding_extends (G <: SignerGrinding {-Independent}) s0 h0 :
  hoare [G(Independent).run :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  exact (independent_derive_extends s0 h0).
qed.
lemma grind_keeps_top_root seed0 root0 :
  hoare [RoleGrind(Independent).run :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (signer_grinding_extends RoleGrind s0 h0); smt(extends_refl merkle_root_witness_extends).
qed.
