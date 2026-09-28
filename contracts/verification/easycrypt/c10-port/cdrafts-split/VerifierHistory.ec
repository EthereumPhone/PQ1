(* External Q2 research: verification issues only public queries. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess RawSigner RawTrial RTailMessages MessageHistory.

module type PublicVerifier (O : PrefixOracle) = {
  proc verify(seed root message : raw_input, sig : raw_signature) : bool { O.hash }
}.

lemma public_verifier_messages (V <: PublicVerifier {-Independent}) messages :
  hoare[V(Independent).verify : r_history_messages Independent.secrethistory messages ==>
    r_history_messages Independent.secrethistory messages].
proof.
  proc (r_history_messages Independent.secrethistory messages) => //.
  exact (hash_keeps_messages messages).
qed.

lemma public_verifier_recorded (V <: PublicVerifier {-Independent}) :
  hoare[V(Independent).verify : history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof.
  proc (history_recorded Independent.rawhistory Independent.queries) => //.
  exact recorded_hash.
qed.

lemma signer_verify_messages messages :
  hoare[RawSigner(Independent).verify : r_history_messages Independent.secrethistory messages ==>
    r_history_messages Independent.secrethistory messages].
proof. exact (public_verifier_messages RawSigner messages). qed.

lemma signer_verify_recorded :
  hoare[RawSigner(Independent).verify : history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof. exact (public_verifier_recorded RawSigner). qed.
